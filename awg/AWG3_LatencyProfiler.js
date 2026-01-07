
import { EventEmitter } from 'events';

/**
 * @file AWG3_LatencyProfiler.js
 * @module AWG3_LatencyProfiler
 * @description
 * Measures end-to-end pipeline latency and annotates tasks with timing metadata.
 * Critical for High-Frequency Trading (HFT) operations where microseconds matter.
 *
 * Provides real-time stats, percentile tracking (p50, p90, p99), and alerts
 * on SLA violations.
 */

/**
 * @typedef {Object} TraceSpan
 * @property {string} id - Span ID
 * @property {string} parentId - Parent Span ID
 * @property {string} name - Operation name
 * @property {number} startTime - Start timestamp (hrtime)
 * @property {number} endTime - End timestamp (hrtime)
 * @property {number} durationMs - Duration in milliseconds
 * @property {Object} tags - Custom tags
 */

/**
 * AWG-3: Latency Profiler
 */
export class LatencyProfiler extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            enabled: true,
            sampleRate: config.sampleRate || 1.0, // 100% sampling by default
            retentionWindowMs: config.retentionWindowMs || 60000, // Keep 1 min of detailed traces
            slaThresholds: config.slaThresholds || {
                'ingest_to_submit': 50, // ms
                'normalization': 5,     // ms
                'signing': 10           // ms
            },
            ...config
        };

        this.traces = new Map(); // active traces
        this.history = [];       // completed traces for stats

        // Circular buffer for stats to avoid memory leaks
        this.maxHistorySize = 10000;

        this.stats = {
            totalSpans: 0,
            violations: 0
        };

        this._startMaintenanceLoop();
        console.log('[AWG-3] LatencyProfiler initialized');
    }

    /**
     * Start a new trace or span
     * @param {string} name - Name of the operation
     * @param {string} [traceId] - Existing trace ID to attach to (or null for new)
     * @param {string} [parentId] - Parent span ID
     * @returns {string} spanId
     */
    startSpan(name, traceId = null, parentId = null) {
        if (!this.config.enabled) return null;
        if (Math.random() > this.config.sampleRate) return null;

        const spanId = this._generateId();
        const effectiveTraceId = traceId || spanId;

        const span = {
            id: spanId,
            traceId: effectiveTraceId,
            parentId,
            name,
            startTime: process.hrtime.bigint(),
            endTime: null,
            tags: {}
        };

        if (!this.traces.has(effectiveTraceId)) {
            this.traces.set(effectiveTraceId, new Map());
        }

        this.traces.get(effectiveTraceId).set(spanId, span);

        return { spanId, traceId: effectiveTraceId };
    }

    /**
     * End a span
     * @param {string} traceId
     * @param {string} spanId
     * @param {Object} tags
     */
    endSpan(traceId, spanId, tags = {}) {
        if (!traceId || !spanId) return;
        const traceMap = this.traces.get(traceId);
        if (!traceMap) return; // Trace not found or already cleaned

        const span = traceMap.get(spanId);
        if (!span) return;

        span.endTime = process.hrtime.bigint();
        // Convert nanoseconds to milliseconds (float)
        span.durationMs = Number(span.endTime - span.startTime) / 1_000_000;
        span.tags = { ...span.tags, ...tags };

        this.stats.totalSpans++;

        // Check SLA
        this._checkSLA(span);

        // If this is a root span (no parent) or we treat it as a discrete unit,
        // we might want to archive the whole trace if it's done.
        // For simplicity, we archive executed spans immediately to history
        this._archiveSpan(span);

        // Cleanup active map if needed (logic simplified)
        traceMap.delete(spanId);
        if (traceMap.size === 0) {
            this.traces.delete(traceId);
        }
    }

    /**
     * Wraps a function execution in a span
     * @param {string} name
     * @param {Function} fn
     * @param {Object} context - { traceId, parentId }
     */
    async measure(name, fn, context = {}) {
        const { spanId, traceId } = this.startSpan(name, context.traceId, context.parentId) || {};

        try {
            const result = await fn();
            if (spanId) this.endSpan(traceId, spanId, { success: true });
            return result;
        } catch (error) {
            if (spanId) this.endSpan(traceId, spanId, { success: false, error: error.message });
            throw error;
        }
    }

    /**
     * Check span against SLA thresholds
     * @private
     */
    _checkSLA(span) {
        const limit = this.config.slaThresholds[span.name];
        if (limit && span.durationMs > limit) {
            this.stats.violations++;
            this.emit('violation', {
                span,
                limit,
                violationMs: span.durationMs - limit
            });
            // console.warn(`[AWG-3] SLA Violation: ${span.name} took ${span.durationMs.toFixed(3)}ms (Limit: ${limit}ms)`);
        }
    }

    /**
     * Archive span to history for statistical analysis
     * @private
     */
    _archiveSpan(span) {
        this.history.push(span);
        if (this.history.length > this.maxHistorySize) {
            this.history.shift(); // Drop oldest
        }
    }

    /**
     * Calculate percentiles for a given operation name
     * @param {string} operationName
     */
    getStats(operationName) {
        const relevantSpans = this.history
            .filter(s => s.name === operationName)
            .map(s => s.durationMs)
            .sort((a, b) => a - b);

        if (relevantSpans.length === 0) return null;

        return {
            operation: operationName,
            count: relevantSpans.length,
            min: relevantSpans[0],
            max: relevantSpans[relevantSpans.length - 1],
            avg: relevantSpans.reduce((a, b) => a + b, 0) / relevantSpans.length,
            p50: this._percentile(relevantSpans, 0.50),
            p90: this._percentile(relevantSpans, 0.90),
            p99: this._percentile(relevantSpans, 0.99)
        };
    }

    /**
     * Generate report of all operations
     */
    getReport() {
        const ops = new Set(this.history.map(s => s.name));
        const report = {};
        for (const op of ops) {
            report[op] = this.getStats(op);
        }
        return report;
    }

    _percentile(sortedArr, p) {
        const index = Math.floor(sortedArr.length * p);
        return sortedArr[index];
    }

    _generateId() {
        return Math.random().toString(36).substring(2, 10);
    }

    /**
     * Periodic cleanup of stale traces
     * @private
     */
    _startMaintenanceLoop() {
        // Cleaning active traces that are stuck is important
        setInterval(() => {
            const now = process.hrtime.bigint();
            for (const [traceId, spanMap] of this.traces) {
                for (const [spanId, span] of spanMap) {
                    const durationNs = now - span.startTime;
                    // If span open for > 5 mins, kill it
                    if (durationNs > 300_000_000_000n) {
                        spanMap.delete(spanId);
                    }
                }
                if (spanMap.size === 0) {
                    this.traces.delete(traceId);
                }
            }
        }, 60000);
    }
}

// -----------------------------------------------------------------------------
// Middleware helper for Express
// -----------------------------------------------------------------------------

/**
 * Express Middleware to profile HTTP requests
 * @param {LatencyProfiler} profiler
 */
export function profilerMiddleware(profiler) {
    return (req, res, next) => {
        const { spanId, traceId } = profiler.startSpan('http_request') || {};

        // Attach to request for downstream use
        req.profilerContext = { traceId, parentId: spanId };

        res.on('finish', () => {
            if (spanId) {
                profiler.endSpan(traceId, spanId, {
                    method: req.method,
                    path: req.path,
                    statusCode: res.statusCode
                });
            }
        });

        next();
    };
}

// -----------------------------------------------------------------------------
// Decorators / Wrappers (since JS doesn't have native decorators in standard yet)
// -----------------------------------------------------------------------------

/**
 * Higher-order function to profile an async function
 */
export function profileAsync(profiler, operationName, fn) {
    return async function(...args) {
        return profiler.measure(operationName, async () => {
            return await fn.apply(this, args);
        });
    };
}

// -----------------------------------------------------------------------------
// Exporters (e.g., to Prometheus or Datadog)
// -----------------------------------------------------------------------------

export class MetricsExporter {
    constructor(profiler) {
        this.profiler = profiler;
    }

    exportToConsole() {
        const report = this.profiler.getReport();
        console.table(Object.values(report).map(r => ({
            Op: r.operation,
            Count: r.count,
            'p99 (ms)': r.p99.toFixed(3),
            'Avg (ms)': r.avg.toFixed(3)
        })));
    }

    // Stub for Prometheus export
    exportToPrometheus() {
        // ... implementation would go here
    }
}

export default LatencyProfiler;
