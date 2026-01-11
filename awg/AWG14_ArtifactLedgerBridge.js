
import { EventEmitter } from 'events';
import crypto from 'crypto';

/**
 * @file AWG14_ArtifactLedgerBridge.js
 * @module AWG14_ArtifactLedgerBridge
 * @description
 * Streams task artifacts to ProtocolLedger for audit continuity.
 * Ensures that every action taken by the system is immutably recorded (or at least
 * buffered for recording) in the master ledger.
 */

/**
 * AWG-14: Artifact Ledger Bridge
 */
export class ArtifactLedgerBridge extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            batchSize: 10,
            flushIntervalMs: 5000,
            ledgerEndpoint: config.ledgerEndpoint || 'mock://ledger',
            ...config
        };

        this.buffer = [];
        this.flushTimer = setInterval(() => this.flush(), this.config.flushIntervalMs);

        console.log('[AWG-14] ArtifactLedgerBridge initialized');
    }

    /**
     * Record an artifact
     * @param {Object} artifact
     */
    record(artifact) {
        const entry = {
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            data: artifact,
            hash: this._hash(artifact)
        };

        this.buffer.push(entry);

        if (this.buffer.length >= this.config.batchSize) {
            this.flush();
        }
    }

    /**
     * Flush buffer to ledger
     */
    async flush() {
        if (this.buffer.length === 0) return;

        const batch = [...this.buffer];
        this.buffer = [];

        try {
            await this._sendToLedger(batch);
            this.emit('flushed', { count: batch.length });
        } catch (error) {
            console.error('[AWG-14] Failed to flush to ledger:', error.message);
            // Re-queue items? Or persistent queue?
            // For now, re-queue (prepend)
            this.buffer.unshift(...batch);
            // Warning: could cause memory leak if ledger is down permanently
        }
    }

    async _sendToLedger(batch) {
        // Mock network call
        // console.log(`[AWG-14] Sending ${batch.length} items to ledger...`);
        return true;
    }

    _hash(data) {
        return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    }

    stop() {
        clearInterval(this.flushTimer);
        this.flush();
    }
}

export default ArtifactLedgerBridge;
