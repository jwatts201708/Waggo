
import { EventEmitter } from 'events';

/**
 * @file AWG6_ReorgResilienceGuard.js
 * @module AWG6_ReorgResilienceGuard
 * @description
 * Protects execution integrity against chain reorganizations (reorgs).
 *
 * Capabilities:
 * - Detects reorgs by monitoring block hash chains.
 * - Flags tasks/bundles with reorg-aware replay policies.
 * - Manages "uncle" risk and re-submits dropped transactions.
 * - Enforces Chain ID validation to prevent cross-chain replay attacks.
 */

/**
 * @typedef {Object} BlockHeader
 * @property {number} number
 * @property {string} hash
 * @property {string} parentHash
 */

/**
 * AWG-6: Reorg Resilience Guard
 */
export class ReorgResilienceGuard extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxReorgDepth: config.maxReorgDepth || 12, // Standard safety for ETH
            confirmationsRequired: config.confirmationsRequired || 1,
            checkIntervalMs: config.checkIntervalMs || 4000,
            ...config
        };

        // Sliding window of block headers
        // Map<blockNumber, BlockHeader>
        this.canonicalChain = new Map();

        // Track sensitive operations pending confirmation
        this.pendingOps = new Map(); // txHash -> OperationContext

        this.latestBlock = 0;
        this.status = 'initialized';

        console.log('[AWG-6] ReorgResilienceGuard initialized');
    }

    start() {
        this.status = 'running';
        this.emit('started');
    }

    stop() {
        this.status = 'stopped';
        this.emit('stopped');
    }

    /**
     * Ingest a new block header to update chain view
     * @param {BlockHeader} header
     */
    processBlock(header) {
        if (this.status !== 'running') return;

        // Check for reorg
        const isReorg = this._detectReorg(header);

        if (isReorg) {
            const reorgDepth = this.latestBlock - header.number + 1; // Approx
            this.log('warn', `REORG DETECTED at block ${header.number}. Depth: ~${reorgDepth}`);
            this.emit('reorg', {
                blockNumber: header.number,
                newHash: header.hash,
                depth: reorgDepth
            });

            this._handleReorg(header);
        }

        // Update canonical chain
        this.canonicalChain.set(header.number, header);
        this.latestBlock = Math.max(this.latestBlock, header.number);

        // Prune old history
        this._pruneHistory();

        // Check confirmations for pending ops
        this._checkConfirmations();
    }

    /**
     * Register an operation to monitor for reorg safety
     * @param {string} txHash
     * @param {Object} context
     */
    trackOperation(txHash, context) {
        this.pendingOps.set(txHash, {
            ...context,
            txHash,
            status: 'pending',
            firstSeenBlock: null,
            confirmations: 0,
            updatedAt: Date.now()
        });
        this.log('debug', `Tracking operation ${txHash}`);
    }

    /**
     * Detect if the new header contradicts our canonical history
     * @private
     */
    _detectReorg(newHeader) {
        // If we have a block at this height...
        if (this.canonicalChain.has(newHeader.number)) {
            const existing = this.canonicalChain.get(newHeader.number);
            // ...and the hash is different
            if (existing.hash !== newHeader.hash) {
                return true;
            }
        }

        // Also check parent hash consistency if we have the parent
        const parentHeight = newHeader.number - 1;
        if (this.canonicalChain.has(parentHeight)) {
            const parent = this.canonicalChain.get(parentHeight);
            if (parent.hash !== newHeader.parentHash) {
                // This implies a reorg happened earlier
                return true;
            }
        }

        return false;
    }

    /**
     * Handle reorg logic: invalidate blocks, notify observers
     * @private
     */
    _handleReorg(forkHeader) {
        // Invalidate all blocks >= forkHeader.number
        // We iterate specifically because we might have higher blocks
        for (const [num, block] of this.canonicalChain) {
            if (num >= forkHeader.number) {
                this.canonicalChain.delete(num);
            }
        }

        // Check which pending ops were affected
        // In a real system, we'd check if the tx is present in the new fork
        // Here we just mark them as 'reorged' so upstream can re-submit
        for (const [hash, op] of this.pendingOps) {
            if (op.blockNumber >= forkHeader.number) {
                this.log('warn', `Operation ${hash} affected by reorg.`);
                op.status = 'reorged';
                op.confirmations = 0;
                this.emit('operation_reorged', op);
            }
        }
    }

    /**
     * Prune history older than maxReorgDepth
     * @private
     */
    _pruneHistory() {
        const safeHeight = this.latestBlock - this.config.maxReorgDepth - 5;
        for (const num of this.canonicalChain.keys()) {
            if (num < safeHeight) {
                this.canonicalChain.delete(num);
            }
        }
    }

    /**
     * Check confirmation counts for pending ops
     * @private
     */
    _checkConfirmations() {
        for (const [hash, op] of this.pendingOps) {
            if (op.status === 'confirmed') continue;

            // If we know which block it was mined in (mocking this here)
            // In reality, we'd need to query the node or check receipts
            if (op.blockNumber && op.blockNumber <= this.latestBlock) {
                const confs = this.latestBlock - op.blockNumber + 1;
                op.confirmations = confs;

                if (confs >= this.config.confirmationsRequired) {
                    op.status = 'confirmed';
                    this.emit('operation_confirmed', op);
                    this.pendingOps.delete(hash); // Stop tracking
                }
            }
        }
    }

    /**
     * Safe execution wrapper with Chain ID check
     * @param {Object} tx
     * @param {number} expectedChainId
     */
    validateChainId(tx, expectedChainId) {
        if (!tx.chainId) return true; // Legacy tx might not have it explicitly in some formats
        if (parseInt(tx.chainId) !== parseInt(expectedChainId)) {
            throw new Error(`Chain ID mismatch: Tx has ${tx.chainId}, expected ${expectedChainId}`);
        }
        return true;
    }

    log(level, msg) {
        // console.log(`[AWG-6][${level}] ${msg}`);
    }
}

// -----------------------------------------------------------------------------
// Resilience Strategies
// -----------------------------------------------------------------------------

/**
 * Strategy to determine if a tx should be replayed after a reorg
 */
export class ReplayStrategy {
    static shouldReplay(operation) {
        // Idempotent operations (swaps with deadlines) might be safe
        // Value transfers might double spend if not careful (though nonce prevents it)

        // If nonce was used on the other fork, we can't just replay exactly same tx usually
        // unless the other fork dropped it completely.

        // Strategy: Always attempt to reconstruct and re-sign with current nonce
        return true;
    }
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

export const CHAINS = {
    MAINNET: 1,
    GOERLI: 5,
    ARBITRUM: 42161,
    OPTIMISM: 10,
    POLYGON: 137
};

export default ReorgResilienceGuard;
