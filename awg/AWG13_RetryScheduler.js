
import { EventEmitter } from 'events';

/**
 * @file AWG13_RetryScheduler.js
 * @module AWG13_RetryScheduler
 * @description
 * Implements exponential backoff with jitter for failed submissions.
 * Handles transient network failures or temporary RPC rejections.
 */

/**
 * AWG-13: Retry Scheduler
 */
export class RetryScheduler extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxRetries: 5,
            baseDelay: 1000,
            maxDelay: 30000,
            jitterFactor: 0.2,
            ...config
        };
        console.log('[AWG-13] RetryScheduler initialized');
    }

    /**
     * Execute a function with retry logic
     * @param {Function} fn - Async function to execute
     * @param {Object} context - Optional context for logging
     */
    async executeWithRetry(fn, context = {}) {
        let attempt = 0;

        while (attempt <= this.config.maxRetries) {
            try {
                return await fn();
            } catch (error) {
                if (attempt === this.config.maxRetries || !this._isRetryable(error)) {
                    throw error;
                }

                const delay = this._calculateBackoff(attempt);
                this.emit('retry', { attempt: attempt + 1, delay, error: error.message });

                await new Promise(resolve => setTimeout(resolve, delay));
                attempt++;
            }
        }
    }

    _calculateBackoff(attempt) {
        // Exponential: base * 2^attempt
        let delay = this.config.baseDelay * Math.pow(2, attempt);

        // Cap at max
        delay = Math.min(delay, this.config.maxDelay);

        // Add Jitter: +/- jitterFactor
        const jitter = delay * this.config.jitterFactor;
        const noise = (Math.random() * jitter * 2) - jitter;

        return Math.floor(delay + noise);
    }

    _isRetryable(error) {
        // Check error code or message
        // e.g. 429 Too Many Requests, 503 Service Unavailable, network timeout
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNRESET') return true;

        const msg = error.message.toLowerCase();
        if (msg.includes('rate limit') || msg.includes('timeout') || msg.includes('nonce too low')) {
            return true;
        }

        return false;
    }
}

export default RetryScheduler;
