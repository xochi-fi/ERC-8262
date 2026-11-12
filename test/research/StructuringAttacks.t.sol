// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SettlementRegistry} from "../../src/SettlementRegistry.sol";
import {ISettlementRegistry} from "../../src/interfaces/ISettlementRegistry.sol";
import {ERC8262Oracle} from "../../src/ERC8262Oracle.sol";
import {ERC8262Verifier} from "../../src/ERC8262Verifier.sol";
import {IUltraVerifier} from "../../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../../src/libraries/ProofTypes.sol";

contract ResearchPassVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @title Anti-structuring research harness (XIP-1 remediation)
/// @notice Each `test_attack_*` passes only when the attack is REFUSED: the attacker
///         does not reach the state they want. Each `test_honest_*` is a legitimate
///         flow that MUST keep working; any honest failure zeroes the metric
///         (scripts/research/attack-metric.sh).
/// @dev Rules for experiments:
///      - The attack goal and its success condition are fixed. Call shapes, setup and
///        helpers MAY change when a design changes the API (for example a jurisdiction
///        threshold registration step, or per-sender trade keys).
///      - Honest flows MAY gain steps the design requires (for example registering a
///        commitment up front), but MUST still end finalized.
///      - Jurisdiction 0's reporting threshold is 10000. 999999 is another
///        jurisdiction's threshold: registered in the Oracle, but not jurisdiction 0's.
contract StructuringAttacks is Test {
    SettlementRegistry internal registry;
    ERC8262Oracle internal oracle;
    ERC8262Verifier internal verifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));
    uint256 internal constant J0_THRESHOLD = 10000;
    uint256 internal constant FOREIGN_THRESHOLD = 999999;
    /// tx_set_hash committed at registration; `_submitPattern` proofs analyse this set.
    bytes32 internal constant PLAN = bytes32(uint256(0xabcd));
    uint256 internal constant STRUCTURING = 1;
    uint256 internal constant VELOCITY = 2;

    uint256 internal _nonce;

    function setUp() public {
        verifier = new ERC8262Verifier(owner);
        uint256[] memory providers = new uint256[](1);
        providers[0] = 1;
        oracle = new ERC8262Oracle(address(verifier), owner, INITIAL_CONFIG, providers);
        ResearchPassVerifier stub = new ResearchPassVerifier();
        vm.startPrank(owner);
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifierInitial(i, address(stub));
        }
        oracle.registerReportingThreshold(bytes32(J0_THRESHOLD));
        oracle.registerReportingThreshold(bytes32(FOREIGN_THRESHOLD));
        vm.stopPrank();
        registry = new SettlementRegistry(address(oracle), [J0_THRESHOLD, FOREIGN_THRESHOLD, 0, 0, 0]);
        vm.warp(1_800_000_000);
    }

    // ---------------------------------------------------------------------
    // Honest flows (must keep working)
    // ---------------------------------------------------------------------

    function test_honest_twoLegs() public {
        bytes32 t = _tradeId("honest-2");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        _finalize(alice, t, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t));
    }

    function test_honest_sixteenLegs() public {
        bytes32 t = _tradeId("honest-16");
        t = _register(alice, t, 16);
        _recordLegs(alice, t, 16, 0);
        _finalize(alice, t, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t));
    }

    /// Legs spread over two days; the pattern proof is made after the last leg and its
    /// window covers every leg.
    function test_honest_legsOverTwoDays() public {
        bytes32 t = _tradeId("honest-spread");
        uint256 start = block.timestamp;
        t = _register(alice, t, 3);
        _recordLegs(alice, t, 3, 1 days);
        _finalize(alice, t, J0_THRESHOLD, block.timestamp - start + 1 hours, block.timestamp);
        assertTrue(_finalized(t));
    }

    /// A user who finalized one split can open another.
    function test_honest_secondTradeAfterFinalized() public {
        bytes32 t1 = _tradeId("honest-a");
        t1 = _register(alice, t1, 2);
        _recordLegs(alice, t1, 2, 0);
        _finalize(alice, t1, J0_THRESHOLD, 1 days, block.timestamp);
        bytes32 t2 = _tradeId("honest-b");
        t2 = _register(alice, t2, 2);
        _recordLegs(alice, t2, 2, 0);
        _finalize(alice, t2, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t2));
    }

    /// A leg fails at its venue: the subject closes the split with a STRUCTURING proof over
    /// the legs that did settle, then settles the remainder as a new split.
    function test_honest_recoverAfterFailedLeg() public {
        bytes32 t1 = _tradeId("honest-failed");
        t1 = _register(alice, t1, 3);
        _recordLegs(alice, t1, 2, 0);
        _abandon(alice, t1);
        bytes32 t2 = _tradeId("honest-remainder");
        t2 = _register(alice, t2, 2);
        _recordLegs(alice, t2, 2, 0);
        _finalize(alice, t2, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t2));
    }

    /// Legs settled but the subject missed the TTL (outage): she resolves the lapsed trade
    /// with a STRUCTURING proof over its legs, then opens and finalizes another.
    function test_honest_resolveLapsedTrade() public {
        bytes32 t1 = _tradeId("honest-lapsed");
        t1 = _register(alice, t1, 2);
        _recordLegs(alice, t1, 2, 0);
        vm.warp(block.timestamp + 7 days + 1);
        _abandon(alice, t1);
        bytes32 t2 = _tradeId("honest-after-lapse");
        t2 = _register(alice, t2, 2);
        _recordLegs(alice, t2, 2, 0);
        _finalize(alice, t2, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t2));
    }

    /// A trade that lapses before any leg settled moved no value and does not block.
    function test_honest_lapsedEmptyTradeDoesNotBlock() public {
        bytes32 t1 = _tradeId("honest-empty");
        t1 = _register(alice, t1, 2);
        vm.warp(block.timestamp + 7 days + 1);
        bytes32 t2 = _tradeId("honest-after-empty");
        t2 = _register(alice, t2, 2);
        _recordLegs(alice, t2, 2, 0);
        _finalize(alice, t2, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t2));
    }

    /// Two splits by the same subject run concurrently and both finalize.
    function test_honest_concurrentTrades() public {
        bytes32 t1 = _tradeId("honest-par-a");
        bytes32 t2 = _tradeId("honest-par-b");
        t1 = _register(alice, t1, 2);
        t2 = _register(alice, t2, 2);
        _recordLegs(alice, t1, 2, 0);
        _recordLegs(alice, t2, 2, 0);
        _finalize(alice, t1, J0_THRESHOLD, 1 days, block.timestamp);
        _finalize(alice, t2, J0_THRESHOLD, 1 days, block.timestamp);
        assertTrue(_finalized(t1) && _finalized(t2));
    }

    // ---------------------------------------------------------------------
    // Attacks (pass = refused)
    // ---------------------------------------------------------------------

    /// One compliance attestation backs a leg of two different trades.
    function test_attack_crossTradeLegReuse() public {
        bytes32 a = _tradeId("reuse-a");
        bytes32 b = _tradeId("reuse-b");
        a = _register(alice, a, 2);
        b = _register(alice, b, 2);
        bytes32 leg = _submitCompliance(alice, 0);
        vm.prank(alice);
        registry.recordSubSettlement(a, 0, leg);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.recordSubSettlement, (b, 0, leg)));
        assertFalse(ok, "attestation reused across trades");
    }

    /// Bob copies Alice's tradeId from the mempool and registers it first.
    function test_attack_tradeIdFrontrun() public {
        bytes32 t = _tradeId("frontrun");
        _register(bob, t, 2);
        (bytes32 plan, bytes memory planInputs) = _planProof(alice, t, 2);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerTrade, (t, 0, 2, plan, planInputs)));
        assertTrue(ok, "victim locked out of her own tradeId");
    }

    /// Pattern proof analysed against another jurisdiction's (higher) threshold.
    function test_attack_foreignThreshold() public {
        bytes32 t = _tradeId("foreign");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        assertFalse(_tryFinalize(alice, t, FOREIGN_THRESHOLD, 1 days, block.timestamp), "foreign threshold accepted");
    }

    /// Pattern proof generated after leg 0 but before leg 1 is recorded; finalized later.
    function test_attack_patternPredatesLastLeg() public {
        bytes32 t = _tradeId("early-pattern");
        t = _register(alice, t, 2);
        vm.warp(block.timestamp + 10 minutes);
        bytes32 leg0 = _submitCompliance(alice, 0);
        bytes32 leg1 = _submitCompliance(alice, 0);
        vm.prank(alice);
        registry.recordSubSettlement(t, 0, leg0);
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = leg0;
        hashes[1] = leg1;
        bytes32 root = _offchainRoot(2, hashes);
        vm.warp(block.timestamp + 20 minutes);
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(alice, STRUCTURING, J0_THRESHOLD, 1 days, root, block.timestamp);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(alice);
        registry.recordSubSettlement(t, 1, leg1);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (t, pattern, inputs)));
        assertFalse(ok, "pattern proof made before the last leg finalized the trade");
    }

    /// Legs over three days, pattern window of one hour: the analysis covers at most the
    /// last leg.
    function test_attack_windowDoesNotCoverLegs() public {
        bytes32 t = _tradeId("short-window");
        t = _register(alice, t, 3);
        _recordLegs(alice, t, 3, 36 hours);
        assertFalse(_tryFinalize(alice, t, J0_THRESHOLD, 1 hours, block.timestamp), "1h window over 3 days of legs");
    }

    /// 17 legs finalized by one pattern proof; the circuit analyses at most 16 amounts.
    function test_attack_moreLegsThanCircuitCapacity() public {
        bytes32 t = _tradeId("seventeen");
        (bytes32 plan, bytes memory planInputs) = _planProof(alice, t, 17);
        vm.prank(alice);
        (bool registered,) =
            address(registry).call(abi.encodeCall(registry.registerTrade, (t, 0, 17, plan, planInputs)));
        if (!registered) return; // refused at registration
        t = registry.computeTradeId(alice, t);
        _recordLegs(alice, t, 17, 0);
        assertFalse(_tryFinalize(alice, t, J0_THRESHOLD, 1 days, block.timestamp), "17 legs on a 16-slot proof");
    }

    /// Alice settles every leg, never finalizes, lets the trade expire, then opens a new
    /// split. The registry must not let her repeat that indefinitely.
    function test_attack_abandonAndRepeat() public {
        bytes32 a = _tradeId("abandon-a");
        a = _register(alice, a, 2);
        _recordLegs(alice, a, 2, 0);
        vm.warp(block.timestamp + 7 days + 1);
        registry.expireTrade(a);
        bytes32 b = _tradeId("abandon-b");
        (bytes32 plan, bytes memory planInputs) = _planProof(alice, b, 2);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerTrade, (b, 0, 2, plan, planInputs)));
        assertFalse(ok, "abandoned settled split did not block the next one");
    }

    /// Expired trade must never read as finalized.
    function test_attack_expiredReadsFinalized() public {
        bytes32 t = _tradeId("expired");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        vm.warp(block.timestamp + 7 days + 1);
        registry.expireTrade(t);
        assertFalse(_finalized(t), "expired trade reads finalized");
    }

    /// One pattern proof finalizes two trades.
    function test_attack_patternReuse() public {
        bytes32 a = _tradeId("pr-a");
        a = _register(alice, a, 2);
        _recordLegs(alice, a, 2, 0);
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(alice, STRUCTURING, J0_THRESHOLD, 1 days, registry.computeSettlementRoot(a), block.timestamp);
        vm.prank(alice);
        registry.finalizeTrade(a, pattern, inputs);
        bytes32 b = _tradeId("pr-b");
        b = _register(alice, b, 2);
        _recordLegs(alice, b, 2, 0);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (b, pattern, inputs)));
        assertFalse(ok, "pattern proof reused");
    }

    /// A VELOCITY analysis stands in for STRUCTURING.
    function test_attack_wrongAnalysisType() public {
        bytes32 t = _tradeId("velocity");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(alice, VELOCITY, J0_THRESHOLD, 1 days, registry.computeSettlementRoot(t), block.timestamp);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (t, pattern, inputs)));
        assertFalse(ok, "velocity proof finalized");
    }

    /// Pattern proof not bound to this trade's legs.
    function test_attack_unboundSettlementRoot() public {
        bytes32 t = _tradeId("unbound");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(alice, STRUCTURING, J0_THRESHOLD, 1 days, bytes32(0), block.timestamp);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (t, pattern, inputs)));
        assertFalse(ok, "unbound pattern proof finalized");
    }

    /// abandonAndRepeat without anyone calling expireTrade: the lapse alone must block.
    /// (Added by lifecycle-gating research.)
    function test_attack_abandonWithoutExpireCall() public {
        bytes32 a = _tradeId("lazy-a");
        a = _register(alice, a, 2);
        _recordLegs(alice, a, 2, 0);
        vm.warp(block.timestamp + 7 days + 1);
        bytes32 b = _tradeId("lazy-b");
        (bytes32 plan, bytes memory planInputs) = _planProof(alice, b, 2);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerTrade, (b, 0, 2, plan, planInputs)));
        assertFalse(ok, "lapsed settled split did not block the next one");
    }

    /// Alice closes a split whose legs settled without a STRUCTURING proof bound to those
    /// legs (no proof, then one bound to nothing), and opens the next split after the lapse.
    /// (Added by lifecycle-gating research.)
    function test_attack_abandonWithoutBoundProof() public {
        bytes32 a = _tradeId("close-a");
        a = _register(alice, a, 2);
        _recordLegs(alice, a, 2, 0);
        vm.prank(alice);
        (bool closed,) =
            address(registry).call(abi.encodeWithSignature("abandonTrade(bytes32,bytes32,bytes)", a, 0, ""));
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(alice, STRUCTURING, J0_THRESHOLD, 1 days, bytes32(0), block.timestamp);
        vm.prank(alice);
        (closed,) =
            address(registry).call(abi.encodeWithSignature("abandonTrade(bytes32,bytes32,bytes)", a, pattern, inputs));
        vm.warp(block.timestamp + 7 days + 1);
        bytes32 b = _tradeId("close-b");
        (bytes32 plan, bytes memory planInputs) = _planProof(alice, b, 2);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerTrade, (b, 0, 2, plan, planInputs)));
        assertFalse(ok, "split closed without a bound structuring proof");
    }

    /// Alice's planned split is structured, so no clean STRUCTURING proof over it exists; she
    /// registers and settles a leg anyway. Refused only if the analysis gates the first leg.
    /// (Added by lifecycle-gating research.)
    function test_attack_legsSettleBeforeAnalysis() public {
        vm.prank(alice);
        (bool registered, bytes memory ret) = address(registry)
            .call(abi.encodeCall(registry.registerTrade, (_tradeId("no-analysis"), 0, 2, bytes32(0), "")));
        if (!registered) return; // refused at registration
        bytes32 t = abi.decode(ret, (bytes32));
        vm.warp(block.timestamp + 1 minutes);
        bytes32 leg = _submitCompliance(alice, 0);
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.recordSubSettlement, (t, 0, leg)));
        assertFalse(ok, "leg settled before any structuring analysis of its split");
    }

    /// Alice commits her analysed set at registration, the legs settle, then she finalizes
    /// with a proof over a different set chosen after the legs paid.
    /// (Added by lifecycle-gating research.)
    function test_attack_analysedSetChosenAfterLegs() public {
        bytes32 t = _tradeId("swap-set");
        t = _register(alice, t, 2);
        _recordLegs(alice, t, 2, 0);
        (bytes32 pattern, bytes memory inputs) = _submitPatternOverSet(
            alice,
            STRUCTURING,
            J0_THRESHOLD,
            1 days,
            bytes32(uint256(0xbeef)),
            registry.computeSettlementRoot(t),
            block.timestamp
        );
        vm.prank(alice);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (t, pattern, inputs)));
        assertFalse(ok, "analysed set picked after the legs settled");
    }

    // ---------------------------------------------------------------------
    // Helpers (MAY change with the design; attack goals MUST NOT)
    // ---------------------------------------------------------------------

    function _tradeId(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    /// Register reference `ref` as `who`; returns the trade id every other call uses.
    function _register(address who, bytes32 ref, uint8 n) internal returns (bytes32 t) {
        (bytes32 plan, bytes memory planInputs) = _planProof(who, ref, n);
        vm.prank(who);
        t = registry.registerTrade(ref, 0, n, plan, planInputs);
    }

    /// STRUCTURING proof over the planned split (set PLAN) for `who` registering `ref`.
    function _planProof(address who, bytes32 ref, uint8 n) internal returns (bytes32, bytes memory) {
        bytes32 root = registry.computePlanRoot(registry.computeTradeId(who, ref), 0, n);
        return _submitPattern(who, STRUCTURING, J0_THRESHOLD, 1 hours, root, block.timestamp);
    }

    /// Submit and record `n` legs, `spacing` seconds apart (first leg after 1 minute).
    function _recordLegs(address who, bytes32 t, uint8 n, uint256 spacing) internal {
        for (uint8 i; i < n; i++) {
            vm.warp(block.timestamp + (i == 0 ? 1 minutes : spacing));
            bytes32 leg = _submitCompliance(who, 0);
            vm.prank(who);
            registry.recordSubSettlement(t, i, leg);
        }
    }

    function _finalize(address who, bytes32 t, uint256 threshold, uint256 window, uint256 ts) internal {
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(who, STRUCTURING, threshold, window, registry.computeSettlementRoot(t), ts);
        vm.prank(who);
        registry.finalizeTrade(t, pattern, inputs);
    }

    /// Close `t` unfinalized with a STRUCTURING proof bound to its recorded legs; the window
    /// reaches back to registration.
    function _abandon(address who, bytes32 t) internal {
        uint256 window = block.timestamp - registry.getSettlement(t).createdAt + 1 hours;
        (bytes32 pattern, bytes memory inputs) =
            _submitPattern(who, STRUCTURING, J0_THRESHOLD, window, registry.computeSettlementRoot(t), block.timestamp);
        vm.prank(who);
        registry.abandonTrade(t, pattern, inputs);
    }

    function _tryFinalize(address who, bytes32 t, uint256 threshold, uint256 window, uint256 ts)
        internal
        returns (bool)
    {
        (bool submitted, bytes memory ret) = address(this)
            .call(
                abi.encodeCall(
                    this.submitPatternExternal, (who, threshold, window, registry.computeSettlementRoot(t), ts)
                )
            );
        if (!submitted) return false; // refused by the Oracle
        (bytes32 pattern, bytes memory inputs) = abi.decode(ret, (bytes32, bytes));
        vm.prank(who);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.finalizeTrade, (t, pattern, inputs)));
        return ok;
    }

    function submitPatternExternal(address who, uint256 threshold, uint256 window, bytes32 root, uint256 ts)
        external
        returns (bytes32, bytes memory)
    {
        return _submitPattern(who, STRUCTURING, threshold, window, root, ts);
    }

    function _finalized(bytes32 t) internal view returns (bool) {
        return registry.getSettlement(t).finalized;
    }

    function _offchainRoot(uint8 n, bytes32[] memory hashes) internal pure returns (bytes32) {
        uint256 modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return bytes32(uint256(keccak256(abi.encode(n, hashes))) % modulus);
    }

    function _proof() internal returns (bytes memory proof) {
        _nonce++;
        proof = new bytes(2144);
        bytes32 n = bytes32(_nonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = n[i];
        }
    }

    function _submitCompliance(address who, uint8 jurisdictionId) internal returns (bytes32) {
        bytes memory proof = _proof();
        bytes memory inputs = abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)),
            bytes32(uint256(uint160(who)))
        );
        vm.prank(who);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, inputs, DEFAULT_PROVIDER_SET_HASH);
        return oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
    }

    function _submitPattern(
        address who,
        uint256 analysisType,
        uint256 threshold,
        uint256 window,
        bytes32 root,
        uint256 ts
    ) internal returns (bytes32, bytes memory inputs) {
        return _submitPatternOverSet(who, analysisType, threshold, window, PLAN, root, ts);
    }

    function _submitPatternOverSet(
        address who,
        uint256 analysisType,
        uint256 threshold,
        uint256 window,
        bytes32 txSet,
        bytes32 root,
        uint256 ts
    ) internal returns (bytes32, bytes memory inputs) {
        bytes memory proof = _proof();
        inputs = abi.encodePacked(
            bytes32(analysisType),
            bytes32(uint256(1)),
            bytes32(threshold),
            bytes32(window),
            txSet,
            bytes32(uint256(uint160(who))),
            root,
            bytes32(ts)
        );
        vm.prank(who);
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, inputs, bytes32(0));
        return (oracle.computeProofHash(proof, ProofTypes.PATTERN), inputs);
    }
}
