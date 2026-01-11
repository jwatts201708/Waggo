
import { EventEmitter } from 'events';

/**
 * @file AWG19_RegionAwareRouter.js
 * @module AWG19_RegionAwareRouter
 * @description
 * Routes tasks to the nearest healthy region/provider.
 * Geo-routing logic for low-latency execution.
 */

/**
 * AWG-19: Region Aware Router
 */
export class RegionAwareRouter extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            localRegion: config.region || 'us-east',
            ...config
        };

        // region -> endpoint url
        this.routes = new Map();

        console.log('[AWG-19] RegionAwareRouter initialized');
    }

    addRoute(region, url) {
        this.routes.set(region, url);
    }

    /**
     * Get route for a task
     * @param {Object} task
     */
    route(task) {
        // Simple logic: prefer local, then fallback
        if (this.routes.has(this.config.localRegion)) {
            return this.routes.get(this.config.localRegion);
        }

        // Fallback to first available
        if (this.routes.size > 0) {
            return this.routes.values().next().value;
        }

        throw new Error('No route available');
    }
}

export default RegionAwareRouter;
