
import { EventEmitter } from 'events';

/**
 * @file AWG11_OpportunityEscrow.js
 * @module AWG11_OpportunityEscrow
 * @description
 * Temporarily holds tasks pending compliance and trust checks.
 * Acts as a buffer/staging area where opportunities wait for asynchronous approval
 * (e.g., from AWG-25 ComplianceTracer or AWG-24 GovernanceLock).
 */

/**
 * AWG-11: Opportunity Escrow
 */
export class OpportunityEscrow extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxEscrowTimeMs: 10000, // 10s default max wait
            ...config
        };
        this.heldItems = new Map(); // id -> { item, timer, approvals: Set }

        console.log('[AWG-11] OpportunityEscrow initialized');
    }

    /**
     * Place an item in escrow
     * @param {Object} item
     * @param {Array<string>} requiredChecks - List of checks to pass (e.g. ['kyc', 'risk'])
     */
    hold(item, requiredChecks = []) {
        if (requiredChecks.length === 0) {
            // No checks needed, pass through
            this.emit('release', item);
            return;
        }

        const id = item.id;
        const timer = setTimeout(() => this._expire(id), this.config.maxEscrowTimeMs);

        this.heldItems.set(id, {
            item,
            timer,
            required: new Set(requiredChecks),
            approved: new Set()
        });

        this.emit('held', { id, required: requiredChecks });
    }

    /**
     * Submit an approval (check passed)
     * @param {string} id
     * @param {string} checkName
     */
    approve(id, checkName) {
        const entry = this.heldItems.get(id);
        if (!entry) return;

        entry.approved.add(checkName);

        // Check if all satisfied
        const allMet = [...entry.required].every(req => entry.approved.has(req));
        if (allMet) {
            this._release(id);
        }
    }

    /**
     * Reject an item
     */
    reject(id, reason) {
        const entry = this.heldItems.get(id);
        if (entry) {
            clearTimeout(entry.timer);
            this.heldItems.delete(id);
            this.emit('rejected', { id, reason });
        }
    }

    _release(id) {
        const entry = this.heldItems.get(id);
        if (entry) {
            clearTimeout(entry.timer);
            this.heldItems.delete(id);
            this.emit('release', entry.item);
        }
    }

    _expire(id) {
        this.reject(id, 'Escrow timeout');
    }
}

export default OpportunityEscrow;
