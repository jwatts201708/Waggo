
import FlashbotsAcquisitionCore from '../awg/AWG1_FlashbotsAcquisitionCore.js';
import OpportunityNormalizer from '../awg/AWG2_OpportunityNormalizer.js';
import LatencyProfiler from '../awg/AWG3_LatencyProfiler.js';

console.log('=== Verifying AWG Modules ===');

async function testModules() {
    try {
        // ---------------------------------------------------------
        // Test AWG-3 Latency Profiler first (to use it for others)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-3: Latency Profiler ---');
        // Set a low threshold for 'start_acquisition' to force a violation for testing
        const profiler = new LatencyProfiler({
            slaThresholds: {
                'start_acquisition': 0.1, // Should trigger violation
                'normalize_opp': 100
            }
        });

        const { spanId, traceId } = profiler.startSpan('awg_test_suite');

        profiler.on('violation', (v) => {
            console.log(`[AWG-3 ALERT] SLA Violation on ${v.span.name}: ${v.violationMs.toFixed(2)}ms over limit`);
        });

        // ---------------------------------------------------------
        // Test AWG-1 Flashbots Acquisition Core
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-1: Flashbots Acquisition Core ---');
        const acquisition = new FlashbotsAcquisitionCore({
            network: 'testnet',
            minProfitThreshold: 0.001,
            simulate: false // Disable sim for fast test
        });

        // Listen for events
        acquisition.on('opportunity', (opp) => {
            console.log(`[AWG-1 Event] Opportunity detected: ${opp.id} (${opp.type})`);
        });

        await profiler.measure('start_acquisition', async () => {
            await acquisition.start();
        }, { traceId, parentId: spanId });

        console.log('AWG-1 Started. Metrics:', acquisition.getMetrics());

        // ---------------------------------------------------------
        // Test AWG-2 Opportunity Normalizer
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-2: Opportunity Normalizer ---');
        const normalizer = new OpportunityNormalizer();

        normalizer.on('normalized', (canon) => {
            console.log(`[AWG-2 Event] Normalized Opportunity: ${canon.traceId} -> Strategy: ${canon.strategy}`);
        });

        normalizer.on('error', (err) => {
            console.error('[AWG-2 Event] Error:', err);
        });

        // Simulate a raw input (e.g. from Uniswap)
        const rawUniswap = {
            sourceId: 'src_001',
            protocol: 'uniswap_v2',
            payload: {
                pair: '0x123...',
                amountIn: 1000000000000000000,
                amountOutMin: 900,
                path: ['0xTokenA', '0xTokenB'],
                tokenIn: '0xTokenA'
            },
            timestamp: Date.now()
        };

        await profiler.measure('normalize_opp', async () => {
            await normalizer.ingest(rawUniswap);
        }, { traceId, parentId: spanId });

        // Simulate a raw input (from AWG-1)
        // We'll manually trigger one to see flow
        const mockAwg1Opp = {
            id: 'opp_flashbots_1',
            type: 'arbitrage',
            confidence: 0.95,
            expectedValue: 0.2,
            transactions: [{ to: '0xTarget', input: '0xData', value: 0 }],
            blockNumber: 12345
        };

        await normalizer.ingest({
            sourceId: 'awg1',
            protocol: 'flashbots_bundle',
            payload: mockAwg1Opp,
            timestamp: Date.now()
        });

        // ---------------------------------------------------------
        // Teardown
        // ---------------------------------------------------------
        console.log('\n--- Teardown ---');
        await acquisition.stop();

        profiler.endSpan(traceId, spanId);

        console.log('\nLatency Report:');
        console.table(Object.values(profiler.getReport()).map(r => ({
            Op: r.operation,
            Count: r.count,
            'Avg (ms)': r.avg.toFixed(3)
        })));

        console.log('\n=== Verification Successful ===');
        process.exit(0);

    } catch (error) {
        console.error('\n=== Verification Failed ===');
        console.error(error);
        process.exit(1);
    }
}

testModules();
