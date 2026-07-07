// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockheadercache.h>
#include <chain.h>
#include <tinyformat.h>
#include <util/check.h>

#include <cstdio>
#include <cstdlib>

BlockHeaderCache g_block_header_cache;

void BlockHeaderCache::Pin(const CBlockIndex* index, const HeaderFields& fields)
{
    LOCK(m_mutex);
    // Drop any stale LRU entry so the pinned one is authoritative.
    if (auto it{m_lru.find(index)}; it != m_lru.end()) {
        m_lru_order.erase(it->second.lru_it);
        m_lru.erase(it);
    }
    m_pinned[index] = fields;
}

void BlockHeaderCache::Unpin(const CBlockIndex* index)
{
    LOCK(m_mutex);
    auto it{m_pinned.find(index)};
    if (it == m_pinned.end()) return;
    InsertLru(index, it->second);
    m_pinned.erase(it);
}

void BlockHeaderCache::Erase(const CBlockIndex* index)
{
    LOCK(m_mutex);
    m_pinned.erase(index);
    if (auto it{m_lru.find(index)}; it != m_lru.end()) {
        m_lru_order.erase(it->second.lru_it);
        m_lru.erase(it);
    }
}

std::optional<HeaderFields> BlockHeaderCache::TryGet(const CBlockIndex* index)
{
    LOCK(m_mutex);
    if (auto it{m_pinned.find(index)}; it != m_pinned.end()) {
        return it->second;
    }
    if (auto it{m_lru.find(index)}; it != m_lru.end()) {
        // Move to front (most recently used).
        m_lru_order.splice(m_lru_order.begin(), m_lru_order, it->second.lru_it);
        return it->second.fields;
    }
    // Miss: read through the backend. This must only happen for entries that
    // have been persisted to the block tree DB (unpersisted ones are pinned).
    if (!m_backend || !index->phashBlock) return std::nullopt;
    HeaderFields fields;
    try {
        if (!m_backend(*index->phashBlock, fields)) return std::nullopt;
    } catch (const std::exception& e) {
        // e.g. dbwrapper_error on a corrupt block tree DB: point reads verify
        // checksums (unlike the iterator-based initial load).
        std::fprintf(stderr, "BlockHeaderCache: backend read failed for block %s: %s\n",
                     index->phashBlock->ToString().c_str(), e.what());
        return std::nullopt;
    }
    InsertLru(index, fields);
    return fields;
}

HeaderFields BlockHeaderCache::Get(const CBlockIndex* index)
{
    if (auto fields{TryGet(index)}) return *fields;
    throw BlockHeaderCacheError(strprintf("BlockHeaderCache: header fields for block %s unavailable",
                                          index->phashBlock ? index->phashBlock->ToString() : "(no hash)"));
}

void BlockHeaderCache::InsertLru(const CBlockIndex* index, const HeaderFields& fields)
{
    AssertLockHeld(m_mutex);
    if (auto it{m_lru.find(index)}; it != m_lru.end()) {
        it->second.fields = fields;
        m_lru_order.splice(m_lru_order.begin(), m_lru_order, it->second.lru_it);
        return;
    }
    m_lru_order.push_front(index);
    m_lru.emplace(index, LruEntry{fields, m_lru_order.begin()});
    while (m_lru.size() > m_lru_capacity) {
        const CBlockIndex* evict{m_lru_order.back()};
        m_lru_order.pop_back();
        m_lru.erase(evict);
    }
}

void BlockHeaderCache::SetBackend(Backend backend)
{
    LOCK(m_mutex);
    m_backend = std::move(backend);
}

void BlockHeaderCache::ResetBackend()
{
    LOCK(m_mutex);
    m_backend = nullptr;
}

size_t BlockHeaderCache::PinnedCount() const
{
    LOCK(m_mutex);
    return m_pinned.size();
}

size_t BlockHeaderCache::LruCount() const
{
    LOCK(m_mutex);
    return m_lru.size();
}

#if defined(__LP64__) || defined(_WIN64)
// Removing the 5 cached header fields (48 bytes) shrinks CBlockIndex from 144
// to 96 bytes on 64-bit platforms.
static_assert(sizeof(CBlockIndex) == 96, "unexpected sizeof(CBlockIndex); lazy block header layout regressed");
#endif

CBlockIndex::CBlockIndex(const CBlockHeader& block)
{
    g_block_header_cache.Pin(this, HeaderFields{block.nVersion, block.hashMerkleRoot, block.nTime, block.nBits, block.nNonce});
}

CBlockIndex::~CBlockIndex()
{
    g_block_header_cache.Erase(this);
}

HeaderFields CBlockIndex::GetHeaderFields() const
{
    return g_block_header_cache.Get(this);
}

void CBlockIndex::SetHeaderFields(int32_t version, const uint256& merkle_root, uint32_t time, uint32_t bits, uint32_t nonce)
{
    g_block_header_cache.Pin(this, HeaderFields{version, merkle_root, time, bits, nonce});
}

void CBlockIndex::SetHeaderFields(const HeaderFields& fields)
{
    g_block_header_cache.Pin(this, fields);
}

CBlockHeader CBlockIndex::GetBlockHeader() const
{
    const HeaderFields fields{GetHeaderFields()};
    CBlockHeader block;
    block.nVersion = fields.nVersion;
    if (pprev)
        block.hashPrevBlock = pprev->GetBlockHash();
    block.hashMerkleRoot = fields.hashMerkleRoot;
    block.nTime = fields.nTime;
    block.nBits = fields.nBits;
    block.nNonce = fields.nNonce;
    return block;
}

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, nHeight, GetBlockMerkleRoot().ToString(), GetBlockHash().ToString());
}

void CChain::SetTip(CBlockIndex& block)
{
    CBlockIndex* pindex = &block;
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

std::vector<uint256> LocatorEntries(const CBlockIndex* index)
{
    int step = 1;
    std::vector<uint256> have;
    if (index == nullptr) return have;

    have.reserve(32);
    while (index) {
        have.emplace_back(index->GetBlockHash());
        if (index->nHeight == 0) break;
        // Exponentially larger steps back, plus the genesis block.
        int height = std::max(index->nHeight - step, 0);
        // Use skiplist.
        index = index->GetAncestor(height);
        if (have.size() > 10) step *= 2;
    }
    return have;
}

CBlockLocator GetLocator(const CBlockIndex* index)
{
    return CBlockLocator{LocatorEntries(index)};
}

const CBlockIndex* CChain::FindFork(const CBlockIndex& index) const
{
    const auto* pindex{&index};
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(*pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime, int height) const
{
    std::pair<int64_t, int> blockparams = std::make_pair(nTime, height);
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), blockparams,
        [](CBlockIndex* pBlock, const std::pair<int64_t, int>& blockparams) -> bool { return pBlock->GetBlockTimeMax() < blockparams.first || pBlock->nHeight < blockparams.second; });
    return (lower == vChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    const CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBitsProof(uint32_t bits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * int64_t(r.GetLow64());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    // First rewind to the last common height (the forking point cannot be past one of the two).
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }
    while (pa != pb) {
        // Jump back until pa and pb have a common "skip" ancestor.
        while (pa->pskip != pb->pskip) {
            // This logic relies on the property that equal-height blocks have equal-height skip
            // pointers.
            Assume(pa->nHeight == pb->nHeight);
            Assume(pa->pskip->nHeight == pb->pskip->nHeight);
            pa = pa->pskip;
            pb = pb->pskip;
        }
        // At this point, pa and pb are different, but have equal pskip. The forking point lies in
        // between pa/pb on the one end, and pa->pskip/pb->pskip on the other end.
        pa = pa->pprev;
        pb = pb->pprev;
    }
    return pa;
}
