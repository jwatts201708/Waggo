
import { EventEmitter } from 'events';
import crypto from 'crypto';

/**
 * @file AWG4_FeeStrategyCalibrator.js
 * @module AWG4_FeeStrategyCalibrator
 * @description
 * Dynamically tunes transaction fees (legacy & EIP-1559) based on live network
 * conditions. It predicts optimal gas prices to ensure inclusion within target
 * blocks while minimizing overpayment.
 *
 * Features:
 * - EIP-1559 BaseFee monitoring and trend analysis
 * - Priority Fee (Tip) dynamic adjustment
 * - Historical gas price oracle
 * - Spike detection and surge protection
 */

/**
 * @typedef {Object} FeeEstimate
 * @property {string} maxFeePerGas - Max total fee (wei)
 * @property {string} maxPriorityFeePerGas - Max miner tip (wei)
 * @property {number} baseFee - Current base fee estimate
 * @property {number} confidence - Probability of inclusion (0-1)
 * @property {number} estimatedWaitTime - ms
 */

/**
 * AWG-4: Fee Strategy Calibrator
 */
export class FeeStrategyCalibrator extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            network: config.network || 'mainnet',
            updateIntervalMs: config.updateIntervalMs || 2000,
            historySize: config.historySize || 100,
            percentiles: config.percentiles || [10, 25, 50, 75, 90],
            maxGasPriceGwei: config.maxGasPriceGwei || 500,
            minPriorityFeeGwei: config.minPriorityFeeGwei || 1.5,
            surgeMultiplier: config.surgeMultiplier || 1.2,
            ...config
        };

        this.history = [];
        this.currentBlock = 0;
        this.status = 'initialized';

        // Mock connection to a gas oracle or node
        this.oracle = new MockGasOracle();

        console.log('[AWG-4] FeeStrategyCalibrator initialized');
    }

    /**
     * Start the calibrator
     */
    async start() {
        if (this.status === 'running') return;
        this.status = 'running';

        this.log('info', 'Starting fee calibration loop...');

        // Initial fetch
        await this._fetchNetworkStats();

        this.interval = setInterval(() => this._fetchNetworkStats(), this.config.updateIntervalMs);
        this.emit('started');
    }

    /**
     * Stop the calibrator
     */
    async stop() {
        if (this.interval) clearInterval(this.interval);
        this.status = 'stopped';
        this.emit('stopped');
    }

    /**
     * Get a fee estimate for a specific priority level
     * @param {string} priority - 'slow', 'standard', 'fast', 'urgent'
     * @returns {FeeEstimate}
     */
    getEstimate(priority = 'standard') {
        if (this.history.length === 0) {
            return this._getFallbackEstimate(priority);
        }

        const latest = this.history[this.history.length - 1];
        const trend = this._analyzeTrend();

        let multiplier = 1.0;
        let priorityGwei = this.config.minPriorityFeeGwei;

        switch (priority) {
            case 'slow':
                multiplier = 1.0;
                priorityGwei = 1.0;
                break;
            case 'standard':
                multiplier = 1.1;
                priorityGwei = 2.0;
                break;
            case 'fast':
                multiplier = 1.25;
                priorityGwei = 5.0;
                break;
            case 'urgent':
                multiplier = 1.5;
                priorityGwei = 15.0;
                break;
            default:
                multiplier = 1.1;
        }

        // Apply surge pricing if trend is rising rapidly
        if (trend === 'rising_fast') {
            multiplier *= this.config.surgeMultiplier;
            priorityGwei *= 1.5;
        }

        const baseFee = latest.baseFee;
        const maxFee = (baseFee * 2) + priorityGwei; // BaseFee usually doubled for safety in EIP-1559

        const estimate = {
            maxFeePerGas: this._toWei(maxFee),
            maxPriorityFeePerGas: this._toWei(priorityGwei),
            baseFee: baseFee,
            confidence: this._calculateConfidence(priority, trend),
            estimatedWaitTime: this._estimateWaitTime(priority),
            timestamp: Date.now()
        };

        // Safety cap check
        if (maxFee > this.config.maxGasPriceGwei) {
            this.log('warn', `Fee estimate exceeds safety cap: ${maxFee} > ${this.config.maxGasPriceGwei}`);
            // Depending on policy, we might clamp or throw. Clamping for now.
            estimate.maxFeePerGas = this._toWei(this.config.maxGasPriceGwei);
        }

        return estimate;
    }

    /**
     * Fetch latest block headers and gas stats
     * @private
     */
    async _fetchNetworkStats() {
        try {
            const stats = await this.oracle.getLatestStats();
            this._addToHistory(stats);

            // Emit update for listeners (e.g. dashboards)
            this.emit('update', stats);

            if (stats.blockNumber > this.currentBlock) {
                this.currentBlock = stats.blockNumber;
                this.log('debug', `New block ${this.currentBlock} observed. BaseFee: ${stats.baseFee} Gwei`);
            }
        } catch (err) {
            this.log('error', 'Failed to fetch network stats', err);
        }
    }

    _addToHistory(stats) {
        this.history.push({
            timestamp: Date.now(),
            ...stats
        });
        if (this.history.length > this.config.historySize) {
            this.history.shift();
        }
    }

    _analyzeTrend() {
        if (this.history.length < 5) return 'stable';

        const recent = this.history.slice(-5);
        const start = recent[0].baseFee;
        const end = recent[recent.length - 1].baseFee;
        const change = (end - start) / start;

        if (change > 0.2) return 'rising_fast';
        if (change > 0.05) return 'rising';
        if (change < -0.2) return 'falling_fast';
        if (change < -0.05) return 'falling';
        return 'stable';
    }

    _calculateConfidence(priority, trend) {
        const baseConfidence = {
            'slow': 0.6,
            'standard': 0.9,
            'fast': 0.98,
            'urgent': 0.999
        }[priority] || 0.9;

        if (trend === 'rising_fast' || trend === 'rising') {
            return Math.max(0.1, baseConfidence - 0.2); // Lower confidence in rising market
        }
        return baseConfidence;
    }

    _estimateWaitTime(priority) {
        // Mock wait times in ms
        return {
            'slow': 60000,
            'standard': 12000, // 1 block
            'fast': 5000,
            'urgent': 1000
        }[priority] || 12000;
    }

    _getFallbackEstimate(priority) {
        // Fallback if no history available
        return {
            maxFeePerGas: this._toWei(50),
            maxPriorityFeePerGas: this._toWei(2),
            baseFee: 20,
            confidence: 0.5,
            estimatedWaitTime: 12000,
            timestamp: Date.now()
        };
    }

    _toWei(gwei) {
        // Simple Gwei -> Wei conversion (mock, using string ops or BigInt)
        // 1 Gwei = 1e9 Wei
        try {
            return (BigInt(Math.floor(gwei * 1000000)) * 1000n).toString();
            // * 1e6 * 1e3 = 1e9. Handling float input for gwei
        } catch (e) {
            return '0';
        }
    }

    log(level, msg, err) {
        // Simple console logger
        const meta = err ? ` | Error: ${err.message}` : '';
        // console.log(`[AWG-4][${level.toUpperCase()}] ${msg}${meta}`);
    }
}

/**
 * Mock Oracle for simulation
 */
class MockGasOracle {
    constructor() {
        this.baseFee = 30; // Start at 30 Gwei
        this.trend = 0; // -1 to 1
    }

    async getLatestStats() {
        // Simulate random walk for baseFee
        const volatility = Math.random() * 4 - 2; // -2 to +2
        this.baseFee = Math.max(10, this.baseFee + volatility);

        return {
            blockNumber: Math.floor(Date.now() / 12000),
            baseFee: parseFloat(this.baseFee.toFixed(2)),
            blobBaseFee: 10, // EIP-4844
            pendingTxCount: Math.floor(Math.random() * 200)
        };
    }
}

// -----------------------------------------------------------------------------
// Advanced Calibration Strategies
// -----------------------------------------------------------------------------

/**
 * Historical Data Analyzer
 * Keeps track of gas usage patterns by time of day
 */
class TimeOfDayAnalyzer {
    constructor() {
        this.hourlyHeatmap = new Array(24).fill(0);
    }

    update(hour, avgFee) {
        this.hourlyHeatmap[hour] = (this.hourlyHeatmap[hour] * 0.9) + (avgFee * 0.1);
    }

    getMultiplier(hour) {
        // If current hour is historically expensive, suggest higher multiplier
        const avg = this.hourlyHeatmap.reduce((a, b) => a + b, 0) / 24;
        if (this.hourlyHeatmap[hour] > avg * 1.5) return 1.2;
        return 1.0;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

export class FeeEstimationError extends Error {
    constructor(msg) {
        super(msg);
        this.name = 'FeeEstimationError';
    }
}

export default FeeStrategyCalibrator;
