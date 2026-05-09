// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/// @title XochiTimelock -- Minimal timelock controller for admin operations
/// @notice Enforces delays on privileged calls to Verifier and Oracle contracts.
///         Two delay tiers: HIGH (24h) for verifier/ownership changes, LOW (6h) for config.
/// @dev Operations are identified by keccak256(target, value, data, salt).
///      Salt allows scheduling the same call multiple times.
contract XochiTimelock {
    /// @notice Operation state: 0 = unscheduled, 1 = executed, >1 = ready timestamp
    mapping(bytes32 operationId => uint256 readyTimestamp) internal _timestamps;

    address public proposer;
    address public guardian;

    uint256 public constant HIGH_DELAY = 24 hours;
    uint256 public constant LOW_DELAY = 6 hours;

    error NotProposer();
    error NotGuardian();
    error NotAuthorized();
    error OperationAlreadyScheduled(bytes32 operationId);
    error OperationNotReady(bytes32 operationId, uint256 readyAt);
    error OperationNotScheduled(bytes32 operationId);
    error OperationAlreadyExecuted(bytes32 operationId);
    error ExecutionFailed(address target, bytes data);
    error ValueMismatch(uint256 sent, uint256 expected);
    error ZeroAddress();

    event OperationScheduled(
        bytes32 indexed operationId, address indexed target, uint256 value, bytes data, uint256 readyAt
    );
    event OperationExecuted(bytes32 indexed operationId, address indexed target, uint256 value, bytes data);
    event OperationCancelled(bytes32 indexed operationId);
    event ProposerUpdated(address indexed oldProposer, address indexed newProposer);
    event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);

    modifier onlyProposer() {
        if (msg.sender != proposer) revert NotProposer();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotProposer();
        _;
    }

    /// @param _proposer Multi-sig address that can schedule and cancel operations
    /// @param _guardian Address that can cancel operations (emergency responder)
    constructor(address _proposer, address _guardian) {
        if (_proposer == address(0)) revert ZeroAddress();
        proposer = _proposer;
        guardian = _guardian;
        emit ProposerUpdated(address(0), _proposer);
        if (_guardian != address(0)) {
            emit GuardianUpdated(address(0), _guardian);
        }
    }

    // -------------------------------------------------------------------------
    // Core operations
    // -------------------------------------------------------------------------

    /// @notice Schedule an operation for future execution
    /// @param target The contract to call
    /// @param value ETH value to send (typically 0)
    /// @param data The calldata (function selector + arguments)
    /// @param salt Allows scheduling duplicate calls (use different salt)
    function schedule(address target, uint256 value, bytes calldata data, bytes32 salt) external onlyProposer {
        bytes32 id = hashOperation(target, value, data, salt);
        if (_timestamps[id] != 0) revert OperationAlreadyScheduled(id);

        uint256 delay = getDelay(bytes4(data[:4]));
        uint256 readyAt = block.timestamp + delay;
        _timestamps[id] = readyAt;

        emit OperationScheduled(id, target, value, data, readyAt);
    }

    /// @notice Execute a scheduled operation after its delay has elapsed
    /// @dev Anyone can execute once the timelock has passed. msg.value MUST equal the
    ///      scheduled `value` exactly to avoid silently locking excess ETH in the timelock.
    function execute(address target, uint256 value, bytes calldata data, bytes32 salt) external payable {
        if (msg.value != value) revert ValueMismatch(msg.value, value);

        bytes32 id = hashOperation(target, value, data, salt);
        uint256 readyAt = _timestamps[id];

        if (readyAt == 0) revert OperationNotScheduled(id);
        if (readyAt == 1) revert OperationAlreadyExecuted(id);
        if (block.timestamp < readyAt) revert OperationNotReady(id, readyAt);

        _timestamps[id] = 1; // mark executed

        (bool success,) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed(target, data);

        emit OperationExecuted(id, target, value, data);
    }

    /// @notice Cancel a scheduled operation
    /// @dev Either the proposer or guardian may cancel.
    function cancel(bytes32 operationId) external {
        if (msg.sender != proposer && msg.sender != guardian) revert NotAuthorized();
        uint256 readyAt = _timestamps[operationId];
        if (readyAt == 0) revert OperationNotScheduled(operationId);
        if (readyAt == 1) revert OperationAlreadyExecuted(operationId);

        delete _timestamps[operationId];
        emit OperationCancelled(operationId);
    }

    // -------------------------------------------------------------------------
    // Self-administration (must go through timelock itself)
    // -------------------------------------------------------------------------

    /// @notice Update the proposer address (must be called via the timelock)
    function updateProposer(address newProposer) external onlySelf {
        if (newProposer == address(0)) revert ZeroAddress();
        address old = proposer;
        proposer = newProposer;
        emit ProposerUpdated(old, newProposer);
    }

    /// @notice Update the guardian address (must be called via the timelock)
    function updateGuardian(address newGuardian) external onlySelf {
        address old = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(old, newGuardian);
    }

    // -------------------------------------------------------------------------
    // Delay classification
    // -------------------------------------------------------------------------

    /// @notice Get the required delay for a function selector
    /// @dev HIGH_DELAY for verifier/ownership changes, LOW_DELAY for config operations.
    ///      Unknown selectors default to HIGH_DELAY (fail-safe).
    function getDelay(bytes4 selector) public pure returns (uint256) {
        // LOW_DELAY (6h): config, TTL, merkle roots, reporting thresholds, revocations.
        // revokeVerifierVersion lives here (not HIGH) because the emergency response to
        // a soundness bug is `pauseProofType` (instant); revocation is permanent
        // housekeeping that can afford a short delay -- and the delay protects against
        // a compromised owner mass-revoking historical versions.
        if (
            selector == bytes4(keccak256("updateProviderConfig(bytes32,string,uint256[])"))
                || selector == bytes4(keccak256("updateAttestationTTL(uint256)"))
                || selector == bytes4(keccak256("registerMerkleRoot(bytes32)"))
                || selector == bytes4(keccak256("revokeMerkleRoot(bytes32)"))
                || selector == bytes4(keccak256("registerReportingThreshold(bytes32)"))
                || selector == bytes4(keccak256("revokeReportingThreshold(bytes32)"))
                || selector == bytes4(keccak256("revokeConfig(bytes32)"))
                || selector == bytes4(keccak256("revokeVerifierVersion(uint8,uint256)"))
        ) {
            return LOW_DELAY;
        }

        // HIGH_DELAY (24h): everything else (verifier updates, ownership, unknown)
        return HIGH_DELAY;
    }

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    /// @notice Compute the operation ID for a given call
    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 salt)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, salt));
    }

    /// @notice Get the state of an operation
    /// @return state 0 = unscheduled, 1 = executed, >1 = pending (ready timestamp)
    function getOperationState(bytes32 operationId) external view returns (uint256 state) {
        return _timestamps[operationId];
    }

    /// @notice Check if an operation is ready to execute
    function isOperationReady(bytes32 operationId) external view returns (bool) {
        uint256 readyAt = _timestamps[operationId];
        return readyAt > 1 && block.timestamp >= readyAt;
    }

    /// @notice Accept ownership of a target contract (for Ownable2Step integration)
    /// @dev Called during setup to accept ownership after transferOwnership
    function acceptOwnership(address target) external onlyProposer {
        (bool success,) = target.call(abi.encodeWithSignature("acceptOwnership()"));
        if (!success) revert ExecutionFailed(target, "");
    }

    receive() external payable {}
}
