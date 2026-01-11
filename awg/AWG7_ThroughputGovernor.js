
import { EventEmitter } from 'events';

/**
 * @file AWG7_ThroughputGovernor.js
 * @module AWG7_ThroughputGovernor
 * @description
 * Applies global QPS (Queries Per Second) and concurrency limits across executors.
 * Ensures the system does not exceed API rate limits (e.g. Infura, Alchemy)
 * or overload internal processing capacity.
 *
 * Implements Token Bucket algorithm and Semaphore patterns.
 */

/**
 * @typedef {Object} RateLimitConfig
 * @property {number} maxQPS - Max queries per second
 * @property {number} burst - Max burst size
 * @property {number} maxConcurrency - Max parallel executions
 */

/**
 * AWG-7: Throughput Governor
 */
export class ThroughputGovernor extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            globalQPS: config.globalQPS || 50,
            globalBurst: config.globalBurst || 10,
            defaultConcurrency: config.defaultConcurrency || 5,
            ...config
        };

        // Token Buckets for different scopes (global, per-provider)
        this.buckets = new Map();

        // Semaphores for concurrency
        this.semaphores = new Map();

        // Initialize global bucket
        this._initBucket('global', this.config.globalQPS, this.config.globalBurst);

        // Start refill loop
        this.refillInterval = setInterval(() => this._refillBuckets(), 100); // 100ms precision

        console.log('[AWG-7] ThroughputGovernor initialized');
    }

    /**
     * Acquire permission to execute an operation
     * @param {string} scope - 'global', 'infura', 'alchemy', etc.
     * @returns {Promise<void>}
     */
    async acquire(scope = 'global') {
        // 1. Concurrency Check
        await this._acquireSemaphore(scope);

        // 2. Rate Limit Check (Token Bucket)
        await this._consumeToken(scope);

        // If we get here, we are good to go
        return;
    }

    /**
     * Release concurrency slot after operation finishes
     * @param {string} scope
     */
    release(scope = 'global') {
        this._releaseSemaphore(scope);
    }

    /**
     * Wrap a function execution with governance
     * @param {string} scope
     * @param {Function} fn
     */
    async execute(scope, fn) {
        try {
            await this.acquire(scope);
            return await fn();
        } finally {
            this.release(scope);
        }
    }

    /**
     * Register a new scope with specific limits
     * @param {string} scope
     * @param {RateLimitConfig} limits
     */
    registerScope(scope, limits) {
        this._initBucket(scope, limits.maxQPS, limits.burst);
        this.semaphores.set(scope, {
            max: limits.maxConcurrency || this.config.defaultConcurrency,
            current: 0,
            queue: []
        });
    }

    // -------------------------------------------------------------------------
    // Token Bucket Logic
    // -------------------------------------------------------------------------

    _initBucket(key, qps, burst) {
        this.buckets.set(key, {
            tokens: burst,
            maxTokens: burst,
            refillRatePerInterval: qps / 10, // /10 because interval is 100ms
            queue: [] // Wait queue for tokens
        });
    }

    _refillBuckets() {
        for (const [key, bucket] of this.buckets) {
            if (bucket.tokens < bucket.maxTokens) {
                bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + bucket.refillRatePerInterval);
                this._processBucketQueue(bucket);
            }
        }
    }

    _processBucketQueue(bucket) {
        while (bucket.queue.length > 0 && bucket.tokens >= 1) {
            bucket.tokens -= 1;
            const resolve = bucket.queue.shift();
            resolve();
        }
    }

    async _consumeToken(scope) {
        // Fallback to global if scope not found (or enforce strictness?)
        // Here we enforce checking specific scope AND global scope if scope != global

        if (scope !== 'global') {
            await this._consumeToken('global'); // Hierarchical limiting
        }

        const bucket = this.buckets.get(scope) || this.buckets.get('global');

        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            return;
        }

        // Wait for token
        return new Promise(resolve => {
            bucket.queue.push(resolve);
        });
    }

    // -------------------------------------------------------------------------
    // Semaphore Logic
    // -------------------------------------------------------------------------

    async _acquireSemaphore(scope) {
        if (!this.semaphores.has(scope)) {
            // Lazy init default
            this.semaphores.set(scope, {
                max: this.config.defaultConcurrency,
                current: 0,
                queue: []
            });
        }

        const sem = this.semaphores.get(scope);
        if (sem.current < sem.max) {
            sem.current++;
            return;
        }

        return new Promise(resolve => {
            sem.queue.push(resolve);
        });
    }

    _releaseSemaphore(scope) {
        const sem = this.semaphores.get(scope);
        if (!sem) return;

        if (sem.queue.length > 0) {
            const next = sem.queue.shift();
            next(); // Hand over slot directly to next in line
        } else {
            sem.current--;
        }
    }

    /**
     * Cleanup
     */
    stop() {
        clearInterval(this.refillInterval);
    }
}

// -----------------------------------------------------------------------------
// Priority Queue Extension
// -----------------------------------------------------------------------------

/**
 * Helper for priority-based throttling
 * Not fully integrated into main bucket logic to save space, but structured here.
 */
class PriorityWaitQueue {
    constructor() {
        this.high = [];
        this.normal = [];
        this.low = [];
    }

    enqueue(resolve, priority) {
        if (priority === 'high') this.high.push(resolve);
        else if (priority === 'low') this.low.push(resolve);
        else this.normal.push(resolve);
    }

    dequeue() {
        if (this.high.length) return this.high.shift();
        if (this.normal.length) return this.normal.shift();
        if (this.low.length) return this.low.shift();
        return null;
    }
}

export default ThroughputGovernor;
