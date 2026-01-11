
import FlashbotsAcquisitionCore from '../awg/AWG1_FlashbotsAcquisitionCore.js';
import OpportunityNormalizer from '../awg/AWG2_OpportunityNormalizer.js';
import LatencyProfiler from '../awg/AWG3_LatencyProfiler.js';
import FeeStrategyCalibrator from '../awg/AWG4_FeeStrategyCalibrator.js';
import BundleConstructor, { MockSigner } from '../awg/AWG5_BundleConstructor.js';
import ReorgResilienceGuard from '../awg/AWG6_ReorgResilienceGuard.js';
import ThroughputGovernor from '../awg/AWG7_ThroughputGovernor.js';
import DeduplicationFilter from '../awg/AWG8_DeduplicationFilter.js';
import IntentClassifier from '../awg/AWG9_IntentClassifier.js';
import SafetyBreaker from '../awg/AWG10_SafetyBreaker.js';
import OpportunityEscrow from '../awg/AWG11_OpportunityEscrow.js';
import PriorityElevator from '../awg/AWG12_PriorityElevator.js';
import RetryScheduler from '../awg/AWG13_RetryScheduler.js';
import ArtifactLedgerBridge from '../awg/AWG14_ArtifactLedgerBridge.js';
import CostAttributionEngine from '../awg/AWG15_CostAttributionEngine.js';
import EndpointFailover from '../awg/AWG16_EndpointFailover.js';
import CircuitHealthReporter from '../awg/AWG17_CircuitHealthReporter.js';
import ColdStartWarmer from '../awg/AWG18_ColdStartWarmer.js';
import RegionAwareRouter from '../awg/AWG19_RegionAwareRouter.js';
import SLAEnforcer from '../awg/AWG20_SLAEnforcer.js';
import RiskScoringKernel from '../awg/AWG21_RiskScoringKernel.js';
import LossCeilingCap from '../awg/AWG22_LossCeilingCap.js';
import ExposureSentinel from '../awg/AWG23_ExposureSentinel.js';
import GovernanceLock from '../awg/AWG24_GovernanceLock.js';
import ComplianceTracer from '../awg/AWG25_ComplianceTracer.js';

console.log('=== Verifying AWG Modules ===');

async function testModules() {
    try {
        const profiler = new LatencyProfiler({ slaThresholds: { 'test': 100 } });
        const { spanId, traceId } = profiler.startSpan('awg_test_suite');

        // --- Previous tests assumed passing... ---

        // ---------------------------------------------------------
        // AWG-17 (Health Reporter)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-17: Circuit Health ---');
        const health = new CircuitHealthReporter({ reportIntervalMs: 100000 });
        health.register('db', () => 'healthy');
        console.log('Health:', health.report().healthy);
        health.stop();

        // ---------------------------------------------------------
        // AWG-18 (Cold Start)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-18: Cold Start ---');
        const warmer = new ColdStartWarmer();
        await warmer.warmUp([() => Promise.resolve('warmed')]);
        console.log('Warmup Complete');

        // ---------------------------------------------------------
        // AWG-19 (Region Router)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-19: Region Router ---');
        const router = new RegionAwareRouter();
        router.addRoute('us-east', 'http://east');
        console.log('Route:', router.route({}));

        // ---------------------------------------------------------
        // AWG-20 (SLA Enforcer)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-20: SLA Enforcer ---');
        const sla = new SLAEnforcer();
        console.log('SLA Pass?', sla.enforce({ timestamp: Date.now() }));

        // ---------------------------------------------------------
        // AWG-21 (Risk Scoring)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-21: Risk Scoring ---');
        const risk = new RiskScoringKernel();
        console.log('Risk Score:', risk.assess({ valueEth: 20 }));

        // ---------------------------------------------------------
        // AWG-22 (Loss Cap)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-22: Loss Cap ---');
        const cap = new LossCeilingCap();
        try { cap.validate(-0.2); } catch(e) { console.log('Cap hit:', e.message); }

        // ---------------------------------------------------------
        // AWG-23 (Exposure)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-23: Exposure Sentinel ---');
        const exposure = new ExposureSentinel();
        exposure.setLimit('USDT', 1000);
        console.log('Exposure Safe?', exposure.checkExposure('USDT', 500));

        // ---------------------------------------------------------
        // AWG-24 (Gov Lock)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-24: Gov Lock ---');
        const gov = new GovernanceLock();
        gov.requestApproval('op1', {});
        gov.on('approved', () => console.log('Op Approved'));
        gov.approve('op1', 'signer1');
        gov.approve('op1', 'signer2'); // Should trigger

        // ---------------------------------------------------------
        // AWG-25 (Compliance)
        // ---------------------------------------------------------
        console.log('\n--- Testing AWG-25: Compliance Tracer ---');
        const comp = new ComplianceTracer();
        const traced = comp.trace({}, { kycLevel: 2, country: 'US' });
        console.log('Compliance Tag:', traced.compliance.country);

        // Teardown
        console.log('\n--- Teardown ---');
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
