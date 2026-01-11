
import { EventEmitter } from 'events';

/**
 * @file AWG17_CircuitHealthReporter.js
 * @module AWG17_CircuitHealthReporter
 * @description
 * Emits periodic health metrics for monitoring.
 * Aggregates health status from all registered subsystems (AWG modules).
 */

/**
 * AWG-17: Circuit Health Reporter
 */
export class CircuitHealthReporter extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            reportIntervalMs: 15000,
            ...config
        };
        this.components = new Map();

        console.log('[AWG-17] CircuitHealthReporter initialized');
        this.start();
    }

    start() {
        this.timer = setInterval(() => this.report(), this.config.reportIntervalMs);
    }

    stop() {
        clearInterval(this.timer);
    }

    /**
     * Register a component to monitor
     * @param {string} name
     * @param {Function} statusFn - Returns 'healthy', 'degraded', or 'down'
     */
    register(name, statusFn) {
        this.components.set(name, statusFn);
    }

    report() {
        const report = {
            timestamp: Date.now(),
            healthy: true,
            components: {}
        };

        for (const [name, fn] of this.components) {
            try {
                const status = fn();
                report.components[name] = status;
                if (status === 'down') report.healthy = false;
            } catch (e) {
                report.components[name] = 'error';
                report.healthy = false;
            }
        }

        this.emit('health_report', report);
        return report;
    }
}

export default CircuitHealthReporter;
