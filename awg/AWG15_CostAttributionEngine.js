
import { EventEmitter } from 'events';

/**
 * @file AWG15_CostAttributionEngine.js
 * @module AWG15_CostAttributionEngine
 * @description
 * Tags execution cost per job for revenue accounting.
 * Calculates Net Profit by subtracting Gas Costs, Flash loan fees, and Service fees
 * from Gross Profit.
 */

/**
 * AWG-15: Cost Attribution Engine
 */
export class CostAttributionEngine extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            nativeTokenPriceUsd: 2000, // Mock price
            ...config
        };
        console.log('[AWG-15] CostAttributionEngine initialized');
    }

    /**
     * Calculate final attribution for a completed job
     * @param {Object} job
     * @param {Object} receipt - Tx receipt
     */
    attribute(job, receipt) {
        const gasUsed = BigInt(receipt.gasUsed);
        const effectiveGasPrice = BigInt(receipt.effectiveGasPrice);
        const costWei = gasUsed * effectiveGasPrice;

        // Protocol fees (e.g. Flash loan 0.09%)
        const protocolFees = this._calculateProtocolFees(job);

        const grossProfitWei = BigInt(job.grossProfitWei || 0);
        const netProfitWei = grossProfitWei - costWei - protocolFees;

        const report = {
            jobId: job.id,
            costWei: costWei.toString(),
            protocolFees: protocolFees.toString(),
            grossProfitWei: grossProfitWei.toString(),
            netProfitWei: netProfitWei.toString(),
            profitability: netProfitWei > 0n ? 'PROFITABLE' : 'LOSS',
            timestamp: Date.now()
        };

        this.emit('attribution', report);
        return report;
    }

    _calculateProtocolFees(job) {
        // Mock logic
        // If job used Aave flashloan, 0.09% fee
        if (job.metadata?.flashloan) {
            const amount = BigInt(job.metadata.flashloanAmount || 0);
            return (amount * 9n) / 10000n;
        }
        return 0n;
    }
}

export default CostAttributionEngine;
