
import { EventEmitter } from 'events';
import crypto from 'crypto';

/**
 * @file AWG8_DeduplicationFilter.js
 * @module AWG8_DeduplicationFilter
 * @description
 * Removes duplicate or near-duplicate opportunities across sources to prevent
 * redundant processing and double-spending.
 *
 * Mechanisms:
 * - Exact hash matching (SHA-256 of payload)
 * - Fuzzy matching (for near-duplicates, e.g. same path, slightly different amount)
 * - Sliding window cache with TTL
 */

/**
 * AWG-8: Deduplication Filter
 */
export class DeduplicationFilter extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            ttlMs: config.ttlMs || 60000, // 1 minute memory
            maxEntries: config.maxEntries || 10000,
            fuzzyThreshold: config.fuzzyThreshold || 0.9,
            ...config
        };

        // Main cache: Map<hash, timestamp>
        this.cache = new Map();

        // Semantic cache for fuzzy matching: Map<key, Object>
        // Key could be "tokenA-tokenB-dex"
        this.semanticCache = new Map();

        this._startCleanupLoop();

        console.log('[AWG-8] DeduplicationFilter initialized');
    }

    /**
     * Check if an item is a duplicate. If not, marks it as seen.
     * @param {Object} item - The opportunity/task object
     * @returns {boolean} - true if duplicate, false if unique
     */
    isDuplicate(item) {
        // 1. Exact Match Check
        const hash = this._generateHash(item);
        if (this.cache.has(hash)) {
            this.emit('duplicate_exact', { id: item.id, hash });
            return true;
        }

        // 2. Semantic/Fuzzy Check
        if (this._isSemanticDuplicate(item)) {
            this.emit('duplicate_semantic', { id: item.id });
            return true;
        }

        // 3. Mark as seen
        this._markSeen(hash, item);
        return false;
    }

    /**
     * Check without marking (dry run)
     */
    check(item) {
        const hash = this._generateHash(item);
        return this.cache.has(hash) || this._isSemanticDuplicate(item, true);
    }

    /**
     * Clear the filter
     */
    clear() {
        this.cache.clear();
        this.semanticCache.clear();
    }

    /**
     * Generate deterministic hash for the item
     * @private
     */
    _generateHash(item) {
        // We need a canonical representation.
        // Assuming item has an ID or we serialize core fields.
        if (item.id) return item.id; // Too simple?

        // Better: Hash the core logic content
        // e.g. for a swap: tokenIn, tokenOut, amount, router
        const payload = JSON.stringify(item.payload || item);
        return crypto.createHash('sha256').update(payload).digest('hex');
    }

    /**
     * Check for semantic duplicates (e.g., same arb on same block from different source)
     * @private
     */
    _isSemanticDuplicate(item, readonly = false) {
        // This requires understanding the item structure.
        // We assume NormalizedOpportunity structure from AWG-2

        if (!item.strategy || !item.actions) return false;

        // Create a semantic key
        // Example: "arbitrage:0xTokenA:0xTokenB:12345" (12345 = targetBlock)
        const key = this._deriveSemanticKey(item);
        if (!key) return false;

        if (this.semanticCache.has(key)) {
            // Found existing entry. Compare values?
            // E.g. if new one is significantly better, maybe allow it?
            // For this module (Deduplication), we usually block strictly.
            // AWG-12 (Priority Elevator) would handle "better replacement".
            return true;
        }

        if (!readonly) {
            this.semanticCache.set(key, {
                timestamp: Date.now(),
                value: item.metadata?.expectedValueEth || 0
            });
        }

        return false;
    }

    _deriveSemanticKey(item) {
        try {
            if (item.strategy === 'arbitrage' || item.strategy === 'swap') {
                const action = item.actions[0];
                const block = item.metadata?.targetBlock || 0;
                return `${item.strategy}:${action.assetIn}:${action.assetOut}:${block}`;
            }
            return null;
        } catch (e) {
            return null;
        }
    }

    _markSeen(hash, item) {
        this.cache.set(hash, Date.now());

        // Enforce max size
        if (this.cache.size > this.config.maxEntries) {
            // Prune oldest (iterator order is insertion order in JS Map)
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
    }

    _startCleanupLoop() {
        setInterval(() => {
            const now = Date.now();
            const expiration = now - this.config.ttlMs;

            // Clean exact cache
            for (const [hash, ts] of this.cache) {
                if (ts < expiration) this.cache.delete(hash);
            }

            // Clean semantic cache
            for (const [key, entry] of this.semanticCache) {
                if (entry.timestamp < expiration) this.semanticCache.delete(key);
            }
        }, 5000);
    }
}

// -----------------------------------------------------------------------------
// Bloom Filter Implementation (Space Efficient)
// -----------------------------------------------------------------------------

/**
 * Simple Bloom Filter for high-volume scenarios where exact Map is too heavy
 */
export class BloomFilter {
    constructor(size = 1000, hashes = 3) {
        this.size = size;
        this.hashes = hashes;
        this.buffer = new Uint8Array(Math.ceil(size / 8));
    }

    add(string) {
        for (let i = 0; i < this.hashes; i++) {
            const idx = this._hash(string, i) % this.size;
            this._setBit(idx);
        }
    }

    has(string) {
        for (let i = 0; i < this.hashes; i++) {
            const idx = this._hash(string, i) % this.size;
            if (!this._getBit(idx)) return false;
        }
        return true;
    }

    _hash(str, seed) {
        // MurmurHash3 or similar preferred. Using simple variant here.
        let h = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i) + seed;
            h = Math.imul(h, 0x01000193);
        }
        return h >>> 0;
    }

    _setBit(idx) {
        const byteIndex = Math.floor(idx / 8);
        const bitIndex = idx % 8;
        this.buffer[byteIndex] |= (1 << bitIndex);
    }

    _getBit(idx) {
        const byteIndex = Math.floor(idx / 8);
        const bitIndex = idx % 8;
        return !!(this.buffer[byteIndex] & (1 << bitIndex));
    }
}

export default DeduplicationFilter;
