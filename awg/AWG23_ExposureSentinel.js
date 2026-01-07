
import { EventEmitter } from 'events';

/**
 * @file AWG23_ExposureSentinel.js
 * @module AWG23_ExposureSentinel
 * @description
 * Tracks cumulative exposure across assets and networks.
 * Ensures the system isn't over-exposed to a single asset (e.g. holding too much USDT).
 */

/**
 * AWG-23: Exposure Sentinel
 */
export class ExposureSentinel extends EventEmitter {
    constructor(config = {}) {
        super();
        this.limits = new Map(); // asset -> maxAmount
        this.current = new Map(); // asset -> currentAmount
        console.log('[AWG-23] ExposureSentinel initialized');
    }

    setLimit(asset, amount) {
        this.limits.set(asset, amount);
    }

    /**
     * Check if adding exposure is safe
     */
    checkExposure(asset, amount) {
        const limit = this.limits.get(asset) || Infinity;
        const current = this.current.get(asset) || 0;

        if (current + amount > limit) {
            return false;
        }
        return true;
    }

    updateExposure(asset, delta) {
        const current = this.current.get(asset) || 0;
        this.current.set(asset, current + delta);
    }
}

export default ExposureSentinel;
