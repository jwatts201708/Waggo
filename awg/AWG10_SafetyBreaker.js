
import { EventEmitter } from 'events';

/**
 * @file AWG10_SafetyBreaker.js
 * @module AWG10_SafetyBreaker
 * @description
 * Halts execution on anomalous loss or health signals.
 * A "Circuit Breaker" for the entire pipeline.
 *
 * Triggers:
 * - Consecutive losses exceeding threshold
 * - Abnormal error rates
 * - External oracle "Kill Switch"
 */

/**
 * AWG-10: Safety Breaker
 */
export class SafetyBreaker extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            maxConsecutiveFailures: 5,
            maxDailyLossEth: 1.0,
            ...config
        };

        this.state = {
            status: 'HEALTHY', // HEALTHY, TRIPPED, WARNING
            consecutiveFailures: 0,
            dailyLoss: 0
        };

        console.log('[AWG-10] SafetyBreaker initialized');
    }

    /**
     * Report an execution result
     * @param {Object} result
     */
    reportResult(result) {
        if (!result.success) {
            this.state.consecutiveFailures++;
        } else {
            this.state.consecutiveFailures = 0;
            // Check for negative profit (slippage loss)
            if (result.profit < 0) {
                this.state.dailyLoss += Math.abs(result.profit);
            }
        }

        this._evaluateHealth();
    }

    /**
     * Check if system is allowed to proceed
     */
    isGo() {
        return this.state.status === 'HEALTHY' || this.state.status === 'WARNING';
    }

    /**
     * Manually trip the breaker
     */
    trip(reason) {
        this.state.status = 'TRIPPED';
        this.emit('trip', reason);
        console.warn(`[AWG-10] SAFETY BREAKER TRIPPED: ${reason}`);
    }

    /**
     * Reset the breaker
     */
    reset() {
        this.state.status = 'HEALTHY';
        this.state.consecutiveFailures = 0;
        this.emit('reset');
    }

    _evaluateHealth() {
        if (this.state.consecutiveFailures >= this.config.maxConsecutiveFailures) {
            this.trip('Max consecutive failures exceeded');
        } else if (this.state.dailyLoss >= this.config.maxDailyLossEth) {
            this.trip('Max daily loss exceeded');
        }
    }
}

export default SafetyBreaker;
