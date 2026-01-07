
import { EventEmitter } from 'events';

/**
 * @file AWG16_EndpointFailover.js
 * @module AWG16_EndpointFailover
 * @description
 * Swaps RPC/providers on soft/hard failure signals.
 * Manages a pool of RPC endpoints (Infura, Alchemy, QuickNode, private nodes)
 * and routes traffic to the healthiest one.
 */

/**
 * AWG-16: Endpoint Failover
 */
export class EndpointFailover extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            checkIntervalMs: 10000,
            ...config
        };

        // Map<url, { status, latency, errorCount, weight }>
        this.endpoints = new Map();

        // Round-robin index
        this.currentIdx = 0;

        console.log('[AWG-16] EndpointFailover initialized');
    }

    addEndpoint(url, weight = 1) {
        this.endpoints.set(url, {
            url,
            weight,
            status: 'active',
            latency: 0,
            errorCount: 0,
            lastCheck: Date.now()
        });
    }

    /**
     * Get the best available endpoint
     */
    getEndpoint() {
        const active = Array.from(this.endpoints.values())
            .filter(e => e.status === 'active')
            .sort((a, b) => a.latency - b.latency); // Prefer low latency

        if (active.length === 0) {
            // Try degraded
            const degraded = Array.from(this.endpoints.values())
                .filter(e => e.status === 'degraded');
            if (degraded.length > 0) return degraded[0].url;
            throw new Error('No healthy endpoints available');
        }

        // Simple strategy: pick lowest latency
        return active[0].url;
    }

    /**
     * Report an error for an endpoint
     */
    reportError(url) {
        const ep = this.endpoints.get(url);
        if (!ep) return;

        ep.errorCount++;
        if (ep.errorCount > 3) {
            ep.status = 'down';
            this.emit('endpoint_down', url);
        } else {
            ep.status = 'degraded';
        }
    }

    /**
     * Report success and latency
     */
    reportSuccess(url, latencyMs) {
        const ep = this.endpoints.get(url);
        if (!ep) return;

        ep.errorCount = 0;
        ep.status = 'active';
        ep.latency = (ep.latency * 0.7) + (latencyMs * 0.3); // EMA
    }
}

export default EndpointFailover;
