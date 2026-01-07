
import FlashbotsAcquisitionCore from '../awg/AWG1_FlashbotsAcquisitionCore.js';
import OpportunityNormalizer from '../awg/AWG2_OpportunityNormalizer.js';
import LatencyProfiler from '../awg/AWG3_LatencyProfiler.js';
import FeeStrategyCalibrator from '../awg/AWG4_FeeStrategyCalibrator.js';
import BundleConstructor, { MockSigner } from '../awg/AWG5_BundleConstructor.js';
import ReorgResilienceGuard from '../awg/AWG6_ReorgResilienceGuard.js';
import ThroughputGovernor from '../awg/AWG7_ThroughputGovernor.js';
import DeduplicationFilter from '../awg/AWG8_DeduplicationFilter.js';

console.log('=== Verifying AWG Modules ===');

async function testModules() {
    try {
        // ---------------------------------------------------------
        // AWG-3 (Profiler)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-3: Latency Profiler ---');
        const profiler = new LatencyProfiler({
            slaThresholds: { 'start_acquisition': 0.1 }
        });
        const { spanId, traceId } = profiler.startSpan('awg_test_suite');
        profiler.on('violation', (v) => console.log(`[AWG-3] SLA Warning: ${v.span.name}`));

        // ---------------------------------------------------------
        // AWG-1 (Acquisition)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-1: Flashbots Acquisition ---');
        const acquisition = new FlashbotsAcquisitionCore({ network: 'testnet', simulate: false });
        await acquisition.start();

        // ---------------------------------------------------------
        // AWG-2 (Normalizer)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-2: Normalizer ---');
        const normalizer = new OpportunityNormalizer();
        const rawOpp = {
            sourceId: 'src_001',
            protocol: 'uniswap_v2',
            payload: { pair: '0x123', amountIn: 100, amountOutMin: 90, path: ['0xA','0xB'], tokenIn: '0xA' },
            timestamp: Date.now()
        };
        await normalizer.ingest(rawOpp);

        // ---------------------------------------------------------
        // AWG-4 (Fee Calibrator)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-4: Fee Strategy Calibrator ---');
        const feeCalibrator = new FeeStrategyCalibrator();
        await feeCalibrator.start();
        const estimate = feeCalibrator.getEstimate('fast');
        console.log('Fee Estimate (Fast):', estimate.maxFeePerGas, 'Wei');
        await feeCalibrator.stop();

        // ---------------------------------------------------------
        // AWG-5 (Bundle Constructor)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-5: Bundle Constructor ---');
        const bundler = new BundleConstructor({ signer: new MockSigner() });
        bundler.enqueue({ to: '0xTarget', value: '1000' }, { priority: 'high' });
        const bundle = await bundler.buildBundle(12345, { maxFeePerGas: '100', maxPriorityFeePerGas: '10' });
        console.log('Bundle Built:', bundle ? bundle.id : 'Failed');

        // ---------------------------------------------------------
        // AWG-6 (Reorg Guard)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-6: Reorg Guard ---');
        const reorgGuard = new ReorgResilienceGuard();
        reorgGuard.start();
        reorgGuard.processBlock({ number: 100, hash: '0xHashA', parentHash: '0xHashP' });
        reorgGuard.processBlock({ number: 101, hash: '0xHashB', parentHash: '0xHashA' });
        // Simulate reorg (block 101 changes hash)
        reorgGuard.processBlock({ number: 101, hash: '0xHashB_Fork', parentHash: '0xHashA' });
        reorgGuard.stop();

        // ---------------------------------------------------------
        // AWG-7 (Throughput Governor)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-7: Throughput Governor ---');
        const governor = new ThroughputGovernor({ globalQPS: 1000 });
        await governor.execute('infura', async () => {
            console.log('Governor allowed execution');
        });
        governor.stop();

        // ---------------------------------------------------------
        // AWG-8 (Deduplication)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-8: Deduplication Filter ---');
        const dedup = new DeduplicationFilter();
        const itemA = { id: 'item_1', payload: 'data' };
        console.log('Is Duplicate (1st time)?', dedup.isDuplicate(itemA)); // False
        console.log('Is Duplicate (2nd time)?', dedup.isDuplicate(itemA)); // True

        // ---------------------------------------------------------
        // Teardown
        // ---------------------------------------------------------
        console.log('\n--- Teardown ---');
        await acquisition.stop();
        profiler.endSpan(traceId, spanId);

        console.log('\n=== Verification Successful ===');
        process.exit(0);

    } catch (error) {
        console.error('\n=== Verification Failed ===');
        console.error(error);
        process.exit(1);
    }
}

testModules();
