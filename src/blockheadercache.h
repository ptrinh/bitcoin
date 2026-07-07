// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKHEADERCACHE_H
#define BITCOIN_BLOCKHEADERCACHE_H

#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <list>
#include <unordered_map>

class CBlockIndex;

//! The five block-header fields that are no longer stored inside CBlockIndex.
//! They remain persisted in the block tree DB (CDiskBlockIndex) and are
//! re-read on demand via BlockHeaderCache.
struct HeaderFields {
    int32_t nVersion{0};
    uint256 hashMerkleRoot{};
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};
};

/**
 * Bounded in-memory cache of block-header fields, keyed by CBlockIndex
 * pointer.
 *
 * Two tiers:
 *  - a PINNED map holding entries that have not yet been persisted to the
 *    block tree DB. These must never be evicted, since they cannot be
 *    re-read from anywhere.
 *  - a bounded LRU holding entries re-read from the block tree DB via the
 *    registered backend.
 *
 * The cache has its own mutex and does not rely on cs_main; accessors are
 * called from net_processing, RPC and validation threads.
 */
class BlockHeaderCache
{
public:
    //! Lazy-read backend: point read of the header fields for a block hash
    //! from the block tree DB. Registered at startup by BlockManager.
    using Backend = std::function<bool(const uint256& hash, HeaderFields& out)>;

    static constexpr size_t DEFAULT_LRU_CAPACITY{20000};

    //! Insert or overwrite a pinned entry (never evicted until Unpin/Erase).
    void Pin(const CBlockIndex* index, const HeaderFields& fields) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Demote a pinned entry to the LRU tier (no-op if not pinned). Called
    //! after the entry has been persisted to the block tree DB.
    void Unpin(const CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Remove any entry (pinned or LRU) for this index. Called from
    //! ~CBlockIndex to avoid dangling keys.
    void Erase(const CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Fetch the header fields for an index: pinned -> LRU -> DB backend.
    //! Aborts with a diagnostic if the fields are unavailable (this should
    //! never happen: unpersisted entries are pinned).
    HeaderFields Get(const CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void SetBackend(Backend backend) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void ResetBackend() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t PinnedCount() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t LruCount() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    using LruList = std::list<const CBlockIndex*>;
    struct LruEntry {
        HeaderFields fields;
        LruList::iterator lru_it;
    };

    void InsertLru(const CBlockIndex* index, const HeaderFields& fields) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    std::unordered_map<const CBlockIndex*, HeaderFields> m_pinned GUARDED_BY(m_mutex);
    std::unordered_map<const CBlockIndex*, LruEntry> m_lru GUARDED_BY(m_mutex);
    //! Most recently used at front.
    LruList m_lru_order GUARDED_BY(m_mutex);
    size_t m_lru_capacity GUARDED_BY(m_mutex){DEFAULT_LRU_CAPACITY};
    Backend m_backend GUARDED_BY(m_mutex);
};

//! Global block header cache (mirrors other validation globals like cs_main).
extern BlockHeaderCache g_block_header_cache;

#endif // BITCOIN_BLOCKHEADERCACHE_H
