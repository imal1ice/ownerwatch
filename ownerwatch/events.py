"""Catalog of admin-surface events worth waking someone up for.

Each entry maps an event signature to an ABI fragment, a severity and a
human description. Severity levels: info < medium < high < critical.
"""
from __future__ import annotations

from dataclasses import dataclass

from web3 import Web3

SEVERITIES = ["info", "medium", "high", "critical"]


@dataclass(frozen=True)
class EventSpec:
    name: str
    signature: str
    abi: dict
    severity: str
    describe: str  # format string using decoded args
    source: str    # which standard this comes from


def _inp(name: str, typ: str, indexed: bool) -> dict:
    return {"name": name, "type": typ, "indexed": indexed}


def _abi(name: str, *inputs: dict) -> dict:
    return {"anonymous": False, "type": "event", "name": name, "inputs": list(inputs)}


CATALOG: list[EventSpec] = [
    # Ownable / Ownable2Step
    EventSpec(
        "OwnershipTransferred", "OwnershipTransferred(address,address)",
        _abi("OwnershipTransferred", _inp("previousOwner", "address", True), _inp("newOwner", "address", True)),
        "critical", "owner changed {previousOwner} -> {newOwner}", "Ownable"),
    EventSpec(
        "OwnershipTransferStarted", "OwnershipTransferStarted(address,address)",
        _abi("OwnershipTransferStarted", _inp("previousOwner", "address", True), _inp("newOwner", "address", True)),
        "high", "ownership transfer started {previousOwner} -> {newOwner} (pending accept)", "Ownable2Step"),
    # AccessControl
    EventSpec(
        "RoleGranted", "RoleGranted(bytes32,address,address)",
        _abi("RoleGranted", _inp("role", "bytes32", True), _inp("account", "address", True), _inp("sender", "address", True)),
        "high", "role {role} granted to {account} by {sender}", "AccessControl"),
    EventSpec(
        "RoleRevoked", "RoleRevoked(bytes32,address,address)",
        _abi("RoleRevoked", _inp("role", "bytes32", True), _inp("account", "address", True), _inp("sender", "address", True)),
        "high", "role {role} revoked from {account} by {sender}", "AccessControl"),
    EventSpec(
        "RoleAdminChanged", "RoleAdminChanged(bytes32,bytes32,bytes32)",
        _abi("RoleAdminChanged", _inp("role", "bytes32", True), _inp("previousAdminRole", "bytes32", True), _inp("newAdminRole", "bytes32", True)),
        "critical", "admin of role {role} changed {previousAdminRole} -> {newAdminRole}", "AccessControl"),
    # ERC-1967 proxies
    EventSpec(
        "Upgraded", "Upgraded(address)",
        _abi("Upgraded", _inp("implementation", "address", True)),
        "critical", "proxy implementation upgraded to {implementation}", "ERC-1967"),
    EventSpec(
        "AdminChanged", "AdminChanged(address,address)",
        _abi("AdminChanged", _inp("previousAdmin", "address", False), _inp("newAdmin", "address", False)),
        "critical", "proxy admin changed {previousAdmin} -> {newAdmin}", "ERC-1967"),
    EventSpec(
        "BeaconUpgraded", "BeaconUpgraded(address)",
        _abi("BeaconUpgraded", _inp("beacon", "address", True)),
        "critical", "proxy beacon changed to {beacon}", "ERC-1967"),
    # Pausable
    EventSpec(
        "Paused", "Paused(address)",
        _abi("Paused", _inp("account", "address", False)),
        "medium", "contract paused by {account}", "Pausable"),
    EventSpec(
        "Unpaused", "Unpaused(address)",
        _abi("Unpaused", _inp("account", "address", False)),
        "medium", "contract unpaused by {account}", "Pausable"),
    # TimelockController
    EventSpec(
        "CallScheduled", "CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)",
        _abi("CallScheduled", _inp("id", "bytes32", True), _inp("index", "uint256", True), _inp("target", "address", False),
             _inp("value", "uint256", False), _inp("data", "bytes", False), _inp("predecessor", "bytes32", False), _inp("delay", "uint256", False)),
        "high", "timelock call scheduled: target {target} value {value} delay {delay}s id {id}", "TimelockController"),
    EventSpec(
        "CallExecuted", "CallExecuted(bytes32,uint256,address,uint256,bytes)",
        _abi("CallExecuted", _inp("id", "bytes32", True), _inp("index", "uint256", True), _inp("target", "address", False),
             _inp("value", "uint256", False), _inp("data", "bytes", False)),
        "high", "timelock call executed: target {target} value {value} id {id}", "TimelockController"),
    EventSpec(
        "Cancelled", "Cancelled(bytes32)",
        _abi("Cancelled", _inp("id", "bytes32", True)),
        "medium", "timelock call cancelled id {id}", "TimelockController"),
    EventSpec(
        "MinDelayChange", "MinDelayChange(uint256,uint256)",
        _abi("MinDelayChange", _inp("oldDuration", "uint256", False), _inp("newDuration", "uint256", False)),
        "critical", "timelock min delay changed {oldDuration}s -> {newDuration}s", "TimelockController"),
    # Legacy Compound-style Timelock (Uniswap, Compound v2 and many forks)
    EventSpec(
        "NewAdmin", "NewAdmin(address)",
        _abi("NewAdmin", _inp("newAdmin", "address", True)),
        "critical", "timelock admin changed to {newAdmin}", "Timelock(legacy)"),
    EventSpec(
        "NewPendingAdmin", "NewPendingAdmin(address)",
        _abi("NewPendingAdmin", _inp("newPendingAdmin", "address", True)),
        "high", "timelock pending admin set to {newPendingAdmin}", "Timelock(legacy)"),
    EventSpec(
        "NewDelay", "NewDelay(uint256)",
        _abi("NewDelay", _inp("newDelay", "uint256", True)),
        "critical", "timelock delay changed to {newDelay}s", "Timelock(legacy)"),
    EventSpec(
        "QueueTransaction", "QueueTransaction(bytes32,address,uint256,string,bytes,uint256)",
        _abi("QueueTransaction", _inp("txHash", "bytes32", True), _inp("target", "address", True), _inp("value", "uint256", False),
             _inp("signature", "string", False), _inp("data", "bytes", False), _inp("eta", "uint256", False)),
        "high", "timelock tx queued: target {target} value {value} sig '{signature}' eta {eta}", "Timelock(legacy)"),
    EventSpec(
        "ExecuteTransaction", "ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)",
        _abi("ExecuteTransaction", _inp("txHash", "bytes32", True), _inp("target", "address", True), _inp("value", "uint256", False),
             _inp("signature", "string", False), _inp("data", "bytes", False), _inp("eta", "uint256", False)),
        "high", "timelock tx executed: target {target} value {value} sig '{signature}'", "Timelock(legacy)"),
    EventSpec(
        "CancelTransaction", "CancelTransaction(bytes32,address,uint256,string,bytes,uint256)",
        _abi("CancelTransaction", _inp("txHash", "bytes32", True), _inp("target", "address", True), _inp("value", "uint256", False),
             _inp("signature", "string", False), _inp("data", "bytes", False), _inp("eta", "uint256", False)),
        "medium", "timelock tx cancelled: target {target} sig '{signature}'", "Timelock(legacy)"),
    # OpenZeppelin Governor and Compound GovernorBravo (shared signatures)
    EventSpec(
        "ProposalCreated", "ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)",
        _abi("ProposalCreated", _inp("proposalId", "uint256", False), _inp("proposer", "address", False), _inp("targets", "address[]", False),
             _inp("values", "uint256[]", False), _inp("signatures", "string[]", False), _inp("calldatas", "bytes[]", False),
             _inp("voteStart", "uint256", False), _inp("voteEnd", "uint256", False), _inp("description", "string", False)),
        "medium", "proposal {proposalId} created by {proposer} with {ntargets} targets: {title}", "Governor"),
    EventSpec(
        "ProposalQueued", "ProposalQueued(uint256,uint256)",
        _abi("ProposalQueued", _inp("proposalId", "uint256", False), _inp("etaSeconds", "uint256", False)),
        "high", "proposal {proposalId} queued, executable at {etaSeconds}", "Governor"),
    EventSpec(
        "ProposalExecuted", "ProposalExecuted(uint256)",
        _abi("ProposalExecuted", _inp("proposalId", "uint256", False)),
        "high", "proposal {proposalId} executed", "Governor"),
    EventSpec(
        "ProposalCanceled", "ProposalCanceled(uint256)",
        _abi("ProposalCanceled", _inp("proposalId", "uint256", False)),
        "medium", "proposal {proposalId} cancelled", "Governor"),
    EventSpec(
        "VotingDelaySet", "VotingDelaySet(uint256,uint256)",
        _abi("VotingDelaySet", _inp("oldVotingDelay", "uint256", False), _inp("newVotingDelay", "uint256", False)),
        "critical", "voting delay changed {oldVotingDelay} -> {newVotingDelay}", "Governor"),
    EventSpec(
        "VotingPeriodSet", "VotingPeriodSet(uint256,uint256)",
        _abi("VotingPeriodSet", _inp("oldVotingPeriod", "uint256", False), _inp("newVotingPeriod", "uint256", False)),
        "critical", "voting period changed {oldVotingPeriod} -> {newVotingPeriod}", "Governor"),
    EventSpec(
        "ProposalThresholdSet", "ProposalThresholdSet(uint256,uint256)",
        _abi("ProposalThresholdSet", _inp("oldProposalThreshold", "uint256", False), _inp("newProposalThreshold", "uint256", False)),
        "critical", "proposal threshold changed {oldProposalThreshold} -> {newProposalThreshold}", "Governor"),
    EventSpec(
        "QuorumNumeratorUpdated", "QuorumNumeratorUpdated(uint256,uint256)",
        _abi("QuorumNumeratorUpdated", _inp("oldQuorumNumerator", "uint256", False), _inp("newQuorumNumerator", "uint256", False)),
        "critical", "quorum numerator changed {oldQuorumNumerator} -> {newQuorumNumerator}", "Governor"),
    EventSpec(
        "TimelockChange", "TimelockChange(address,address)",
        _abi("TimelockChange", _inp("oldTimelock", "address", False), _inp("newTimelock", "address", False)),
        "critical", "governor timelock changed {oldTimelock} -> {newTimelock}", "Governor"),
    EventSpec(
        "NewImplementation", "NewImplementation(address,address)",
        _abi("NewImplementation", _inp("oldImplementation", "address", False), _inp("newImplementation", "address", False)),
        "critical", "governor implementation changed {oldImplementation} -> {newImplementation}", "GovernorBravo"),
    # Aragon OS (Lido and other Aragon DAOs)
    EventSpec(
        "SetApp", "SetApp(bytes32,bytes32,address)",
        _abi("SetApp", _inp("namespace", "bytes32", True), _inp("appId", "bytes32", True), _inp("app", "address", False)),
        "critical", "Aragon kernel app set: appId {appId} -> {app}", "AragonOS"),
    EventSpec(
        "SetPermission", "SetPermission(address,address,bytes32,bool)",
        _abi("SetPermission", _inp("entity", "address", True), _inp("app", "address", True), _inp("role", "bytes32", True), _inp("allowed", "bool", False)),
        "high", "Aragon permission {role} on {app} for {entity} set to {allowed}", "AragonOS"),
    EventSpec(
        "ChangePermissionManager", "ChangePermissionManager(address,bytes32,address)",
        _abi("ChangePermissionManager", _inp("app", "address", True), _inp("role", "bytes32", True), _inp("manager", "address", True)),
        "critical", "Aragon permission manager for {role} on {app} changed to {manager}", "AragonOS"),
    EventSpec(
        "StartVote", "StartVote(uint256,address,string)",
        _abi("StartVote", _inp("voteId", "uint256", True), _inp("creator", "address", True), _inp("metadata", "string", False)),
        "medium", "Aragon vote {voteId} started by {creator}: {metadata}", "AragonVoting"),
    EventSpec(
        "ExecuteVote", "ExecuteVote(uint256)",
        _abi("ExecuteVote", _inp("voteId", "uint256", True)),
        "high", "Aragon vote {voteId} executed", "AragonVoting"),
    # Aave V3 PoolAddressesProvider and PoolConfigurator
    EventSpec("PoolUpdated", "PoolUpdated(address,address)",
              _abi("PoolUpdated", _inp("oldAddress", "address", True), _inp("newAddress", "address", True)),
              "critical", "Aave Pool implementation changed {oldAddress} -> {newAddress}", "AaveV3"),
    EventSpec("PoolConfiguratorUpdated", "PoolConfiguratorUpdated(address,address)",
              _abi("PoolConfiguratorUpdated", _inp("oldAddress", "address", True), _inp("newAddress", "address", True)),
              "critical", "Aave PoolConfigurator changed {oldAddress} -> {newAddress}", "AaveV3"),
    EventSpec("ACLAdminUpdated", "ACLAdminUpdated(address,address)",
              _abi("ACLAdminUpdated", _inp("oldAddress", "address", True), _inp("newAddress", "address", True)),
              "critical", "Aave ACL admin changed {oldAddress} -> {newAddress}", "AaveV3"),
    EventSpec("ACLManagerUpdated", "ACLManagerUpdated(address,address)",
              _abi("ACLManagerUpdated", _inp("oldAddress", "address", True), _inp("newAddress", "address", True)),
              "critical", "Aave ACL manager changed {oldAddress} -> {newAddress}", "AaveV3"),
    EventSpec("PriceOracleUpdated", "PriceOracleUpdated(address,address)",
              _abi("PriceOracleUpdated", _inp("oldAddress", "address", True), _inp("newAddress", "address", True)),
              "critical", "Aave price oracle changed {oldAddress} -> {newAddress}", "AaveV3"),
    # Aave Governance V3 PayloadsController (what actually executes Aave proposals, per network)
    EventSpec("PayloadCreated", "PayloadCreated(uint40,address,(address,bool,uint8,uint256,string,bytes)[],uint8)",
              _abi("PayloadCreated", _inp("payloadId", "uint40", True), _inp("creator", "address", True),
                   {"name": "actions", "type": "tuple[]", "indexed": False, "components": [
                       _inp("target", "address", False), _inp("withDelegateCall", "bool", False), _inp("accessLevel", "uint8", False),
                       _inp("value", "uint256", False), _inp("signature", "string", False), _inp("callData", "bytes", False)]},
                   _inp("maximumAccessLevelRequired", "uint8", True)),
              "medium", "Aave payload {payloadId} created by {creator}, access level {maximumAccessLevelRequired}, {nactions} actions", "AavePayloads"),
    EventSpec("PayloadQueued", "PayloadQueued(uint40)", _abi("PayloadQueued", _inp("payloadId", "uint40", False)),
              "high", "Aave payload {payloadId} queued for execution after the timelock", "AavePayloads"),
    EventSpec("PayloadExecuted", "PayloadExecuted(uint40)", _abi("PayloadExecuted", _inp("payloadId", "uint40", False)),
              "high", "Aave payload {payloadId} executed", "AavePayloads"),
    EventSpec("PayloadCancelled", "PayloadCancelled(uint40)", _abi("PayloadCancelled", _inp("payloadId", "uint40", False)),
              "medium", "Aave payload {payloadId} cancelled by the guardian", "AavePayloads"),
    EventSpec("ExecutorSet", "ExecutorSet(uint8,address,uint40)",
              _abi("ExecutorSet", _inp("accessLevel", "uint8", True), _inp("executor", "address", True), _inp("delay", "uint40", False)),
              "critical", "Aave executor for access level {accessLevel} set to {executor} with delay {delay}s", "AavePayloads"),
    EventSpec("GuardianUpdated", "GuardianUpdated(address,address)",
              _abi("GuardianUpdated", _inp("oldGuardian", "address", False), _inp("newGuardian", "address", False)),
              "critical", "Aave guardian changed {oldGuardian} -> {newGuardian}", "AavePayloads"),
    EventSpec("AddressSetAsProxy", "AddressSetAsProxy(bytes32,address,address,address)",
              _abi("AddressSetAsProxy", _inp("id", "bytes32", True), _inp("proxyAddress", "address", True),
                   _inp("oldImplementationAddress", "address", False), _inp("newImplementationAddress", "address", True)),
              "critical", "Aave address {id} proxy {proxyAddress} re-implemented -> {newImplementationAddress}", "AaveV3"),
    EventSpec("ReservePaused", "ReservePaused(address,bool)",
              _abi("ReservePaused", _inp("asset", "address", True), _inp("paused", "bool", False)),
              "medium", "Aave reserve {asset} paused={paused}", "AaveV3"),
    EventSpec("ReserveFrozen", "ReserveFrozen(address,bool)",
              _abi("ReserveFrozen", _inp("asset", "address", True), _inp("frozen", "bool", False)),
              "medium", "Aave reserve {asset} frozen={frozen}", "AaveV3"),
    # Morpho Blue and MetaMorpho vaults
    EventSpec("SetOwner", "SetOwner(address)",
              _abi("SetOwner", _inp("newOwner", "address", True)),
              "critical", "Morpho owner set to {newOwner}", "Morpho"),
    EventSpec("SetFeeRecipient", "SetFeeRecipient(address)",
              _abi("SetFeeRecipient", _inp("newFeeRecipient", "address", True)),
              "high", "Morpho fee recipient set to {newFeeRecipient}", "Morpho"),
    EventSpec("EnableIrm", "EnableIrm(address)",
              _abi("EnableIrm", _inp("irm", "address", True)),
              "high", "Morpho IRM enabled {irm}", "Morpho"),
    EventSpec("SetCurator", "SetCurator(address)",
              _abi("SetCurator", _inp("newCurator", "address", True)),
              "critical", "MetaMorpho curator set to {newCurator}", "MetaMorpho"),
    EventSpec("SetIsAllocator", "SetIsAllocator(address,bool)",
              _abi("SetIsAllocator", _inp("allocator", "address", True), _inp("isAllocator", "bool", False)),
              "high", "MetaMorpho allocator {allocator} set to {isAllocator}", "MetaMorpho"),
    EventSpec("SetGuardian", "SetGuardian(address,address)",
              _abi("SetGuardian", _inp("caller", "address", True), _inp("guardian", "address", True)),
              "critical", "MetaMorpho guardian set to {guardian} by {caller}", "MetaMorpho"),
    EventSpec("SubmitTimelock", "SubmitTimelock(uint256)",
              _abi("SubmitTimelock", _inp("newTimelock", "uint256", False)),
              "high", "MetaMorpho timelock change submitted: {newTimelock}s", "MetaMorpho"),
    EventSpec("SetTimelock", "SetTimelock(address,uint256)",
              _abi("SetTimelock", _inp("caller", "address", True), _inp("newTimelock", "uint256", False)),
              "critical", "MetaMorpho timelock set to {newTimelock}s by {caller}", "MetaMorpho"),
    EventSpec("SubmitCap", "SubmitCap(address,bytes32,uint256)",
              _abi("SubmitCap", _inp("caller", "address", True), _inp("id", "bytes32", True), _inp("cap", "uint256", False)),
              "medium", "MetaMorpho cap submitted for market {id}: {cap} by {caller}", "MetaMorpho"),
    EventSpec("SetCap", "SetCap(address,bytes32,uint256)",
              _abi("SetCap", _inp("caller", "address", True), _inp("id", "bytes32", True), _inp("cap", "uint256", False)),
              "high", "MetaMorpho cap set for market {id}: {cap} by {caller}", "MetaMorpho"),
    # Lido core
    EventSpec("Stopped", "Stopped()", _abi("Stopped"), "critical", "Lido stopped", "Lido"),
    EventSpec("Resumed", "Resumed()", _abi("Resumed"), "high", "Lido resumed", "Lido"),
    EventSpec("StakingPaused", "StakingPaused()", _abi("StakingPaused"), "high", "Lido staking paused", "Lido"),
    EventSpec("StakingResumed", "StakingResumed()", _abi("StakingResumed"), "medium", "Lido staking resumed", "Lido"),
    EventSpec("StakingLimitSet", "StakingLimitSet(uint256,uint256)",
              _abi("StakingLimitSet", _inp("maxStakeLimit", "uint256", False), _inp("stakeLimitIncreasePerBlock", "uint256", False)),
              "medium", "Lido staking limit set: max {maxStakeLimit}, +{stakeLimitIncreasePerBlock}/block", "Lido"),
    # Safe (Gnosis Safe)
    EventSpec(
        "AddedOwner", "AddedOwner(address)",
        _abi("AddedOwner", _inp("owner", "address", False)),
        "critical", "Safe owner added {owner}", "Safe"),
    EventSpec(
        "RemovedOwner", "RemovedOwner(address)",
        _abi("RemovedOwner", _inp("owner", "address", False)),
        "critical", "Safe owner removed {owner}", "Safe"),
    EventSpec(
        "ChangedThreshold", "ChangedThreshold(uint256)",
        _abi("ChangedThreshold", _inp("threshold", "uint256", False)),
        "critical", "Safe threshold changed to {threshold}", "Safe"),
    EventSpec(
        "EnabledModule", "EnabledModule(address)",
        _abi("EnabledModule", _inp("module", "address", False)),
        "critical", "Safe module enabled {module}", "Safe"),
    EventSpec(
        "DisabledModule", "DisabledModule(address)",
        _abi("DisabledModule", _inp("module", "address", False)),
        "high", "Safe module disabled {module}", "Safe"),
    EventSpec(
        "ChangedGuard", "ChangedGuard(address)",
        _abi("ChangedGuard", _inp("guard", "address", False)),
        "critical", "Safe guard changed to {guard}", "Safe"),
    EventSpec(
        "ExecutionFromModuleSuccess", "ExecutionFromModuleSuccess(address)",
        _abi("ExecutionFromModuleSuccess", _inp("module", "address", True)),
        "high", "Safe executed a transaction via module {module}, bypassing the signer queue", "Safe"),
    EventSpec(
        "ExecutionFromModuleFailure", "ExecutionFromModuleFailure(address)",
        _abi("ExecutionFromModuleFailure", _inp("module", "address", True)),
        "medium", "Safe module {module} attempted a transaction that failed", "Safe"),
    EventSpec(
        "ExecutionSuccess", "ExecutionSuccess(bytes32,uint256)",
        _abi("ExecutionSuccess", _inp("txHash", "bytes32", False), _inp("payment", "uint256", False)),
        "info", "Safe transaction executed {txHash}", "Safe"),
    EventSpec(
        "ExecutionFailure", "ExecutionFailure(bytes32,uint256)",
        _abi("ExecutionFailure", _inp("txHash", "bytes32", False), _inp("payment", "uint256", False)),
        "medium", "Safe transaction reverted on execution {txHash}", "Safe"),
    EventSpec(
        "ChangedFallbackHandler", "ChangedFallbackHandler(address)",
        _abi("ChangedFallbackHandler", _inp("handler", "address", False)),
        "high", "Safe fallback handler changed to {handler}", "Safe"),
]


def _single(name: str, typ: str, arg: str, indexed: bool, severity: str, describe: str, source: str) -> EventSpec:
    return EventSpec(name, f"{name}({typ})", _abi(name, _inp(arg, typ, indexed)), severity, describe, source)


def _bare(name: str, severity: str, describe: str, source: str) -> EventSpec:
    return EventSpec(name, f"{name}()", _abi(name), severity, describe, source)


_EXTERNAL_CALLS = {"name": "calls", "type": "tuple[]", "indexed": False, "components": [
    _inp("target", "address", False), _inp("value", "uint96", False), _inp("payload", "bytes", False)]}
_DG_CONTEXT = {"name": "context", "type": "tuple", "indexed": False, "components": [
    _inp("state", "uint8", False), _inp("enteredAt", "uint40", False), _inp("vetoSignallingActivatedAt", "uint40", False),
    _inp("signallingEscrow", "address", False), _inp("rageQuitRound", "uint8", False),
    _inp("vetoSignallingReactivationTime", "uint40", False), _inp("normalOrVetoCooldownExitedAt", "uint40", False),
    _inp("rageQuitEscrow", "address", False), _inp("configProvider", "address", False)]}
# Lido Dual Governance states, in the contract's enum order.
DG_STATES = ["NotInitialized", "Normal", "VetoSignalling", "VetoSignallingDeactivation", "VetoCooldown", "RageQuit"]

CATALOG += [
    # Sky (MakerDAO) governance: DSChief elects the hat; DSPause owner/authority. Spells themselves are DSNote
    # notes, decoded from NOTE_SPECS below.
    _single("Lift", "address", "whom", True, "critical", "new hat lifted in the chief: {whom}", "DSChief"),
    _single("LogSetOwner", "address", "owner", True, "critical", "owner set to {owner}", "DSAuth"),
    _single("LogSetAuthority", "address", "authority", True, "critical", "authority set to {authority}", "DSAuth"),
    # Lido Dual Governance and its Emergency Protected Timelock. Executions emit ProposalExecuted(uint256),
    # the same signature as Governor's, so the Governor entry above decodes them.
    EventSpec("ProposalSubmitted", "ProposalSubmitted(uint256,address,(address,uint96,bytes)[])",
              _abi("ProposalSubmitted", _inp("id", "uint256", True), _inp("executor", "address", True), _EXTERNAL_CALLS),
              "medium", "timelock proposal {id} submitted for executor {executor}, {ncalls} calls", "EmergencyProtectedTimelock"),
    _single("ProposalScheduled", "uint256", "id", True, "high", "timelock proposal {id} scheduled for execution", "EmergencyProtectedTimelock"),
    _single("ProposalsCancelledTill", "uint256", "proposalId", False, "medium", "all timelock proposals up to {proposalId} cancelled", "EmergencyProtectedTimelock"),
    _single("GovernanceSet", "address", "newGovernance", False, "critical", "timelock governance set to {newGovernance}", "EmergencyProtectedTimelock"),
    _single("AdminExecutorSet", "address", "newAdminExecutor", False, "critical", "timelock admin executor set to {newAdminExecutor}", "EmergencyProtectedTimelock"),
    _single("AfterSubmitDelaySet", "uint32", "newAfterSubmitDelay", False, "critical", "timelock after-submit delay set to {newAfterSubmitDelay}s", "EmergencyProtectedTimelock"),
    _single("AfterScheduleDelaySet", "uint32", "newAfterScheduleDelay", False, "critical", "timelock after-schedule delay set to {newAfterScheduleDelay}s", "EmergencyProtectedTimelock"),
    _single("EmergencyGovernanceSet", "address", "newEmergencyGovernance", False, "critical", "emergency governance set to {newEmergencyGovernance}", "EmergencyProtectedTimelock"),
    _single("EmergencyActivationCommitteeSet", "address", "newActivationCommittee", False, "critical", "emergency activation committee set to {newActivationCommittee}", "EmergencyProtectedTimelock"),
    _single("EmergencyExecutionCommitteeSet", "address", "newExecutionCommittee", False, "critical", "emergency execution committee set to {newExecutionCommittee}", "EmergencyProtectedTimelock"),
    _single("EmergencyProtectionEndDateSet", "uint40", "newEmergencyProtectionEndDate", False, "critical", "emergency protection end date set to {newEmergencyProtectionEndDate}", "EmergencyProtectedTimelock"),
    _single("EmergencyModeDurationSet", "uint32", "newEmergencyModeDuration", False, "critical", "emergency mode duration set to {newEmergencyModeDuration}s", "EmergencyProtectedTimelock"),
    _bare("EmergencyModeActivated", "critical", "emergency mode activated", "EmergencyProtectedTimelock"),
    _bare("EmergencyModeDeactivated", "high", "emergency mode deactivated", "EmergencyProtectedTimelock"),
    EventSpec("ProposalSubmitted", "ProposalSubmitted(address,uint256,string)",
              _abi("ProposalSubmitted", _inp("proposerAccount", "address", True), _inp("proposalId", "uint256", True), _inp("metadata", "string", False)),
              "medium", "Dual Governance proposal {proposalId} submitted by {proposerAccount}: {metadata}", "DualGovernance"),
    EventSpec("DualGovernanceStateChanged", "DualGovernanceStateChanged(uint8,uint8,(uint8,uint40,uint40,address,uint8,uint40,uint40,address,address))",
              _abi("DualGovernanceStateChanged", _inp("from", "uint8", True), _inp("to", "uint8", True), _DG_CONTEXT),
              "high", "Dual Governance state {fromState} -> {toState}", "DualGovernance"),
    EventSpec("ProposerRegistered", "ProposerRegistered(address,address)",
              _abi("ProposerRegistered", _inp("proposerAccount", "address", True), _inp("executor", "address", True)),
              "critical", "Dual Governance proposer {proposerAccount} registered with executor {executor}", "DualGovernance"),
    EventSpec("ProposerUnregistered", "ProposerUnregistered(address,address)",
              _abi("ProposerUnregistered", _inp("proposerAccount", "address", True), _inp("executor", "address", True)),
              "critical", "Dual Governance proposer {proposerAccount} unregistered", "DualGovernance"),
    EventSpec("ProposerExecutorSet", "ProposerExecutorSet(address,address)",
              _abi("ProposerExecutorSet", _inp("proposerAccount", "address", True), _inp("executor", "address", True)),
              "critical", "Dual Governance executor of {proposerAccount} set to {executor}", "DualGovernance"),
    _single("ResealCommitteeSet", "address", "resealCommittee", True, "critical", "reseal committee set to {resealCommittee}", "DualGovernance"),
    _single("ResealManagerSet", "address", "resealManager", True, "critical", "reseal manager set to {resealManager}", "DualGovernance"),
    _single("TiebreakerCommitteeSet", "address", "newTiebreakerCommittee", False, "critical", "tiebreaker committee set to {newTiebreakerCommittee}", "DualGovernance"),
    _single("TiebreakerActivationTimeoutSet", "uint32", "newTiebreakerActivationTimeout", False, "critical", "tiebreaker activation timeout set to {newTiebreakerActivationTimeout}s", "DualGovernance"),
    _single("ProposalsCancellerSet", "address", "proposalsCanceller", True, "critical", "proposals canceller set to {proposalsCanceller}", "DualGovernance"),
    _single("ConfigProviderSet", "address", "newConfigProvider", True, "critical", "Dual Governance config provider set to {newConfigProvider}", "DualGovernance"),
    _single("SealableWithdrawalBlockerAdded", "address", "sealable", False, "high", "sealable withdrawal blocker added: {sealable}", "DualGovernance"),
    _single("SealableWithdrawalBlockerRemoved", "address", "sealable", False, "high", "sealable withdrawal blocker removed: {sealable}", "DualGovernance"),
    # Rocket Pool DAOs: protocol DAO proposals, the shared oDAO/security council proposals, contract upgrades.
    EventSpec("ProposalExecuted", "ProposalExecuted(uint256,address,uint256)",
              _abi("ProposalExecuted", _inp("proposalID", "uint256", True), _inp("executor", "address", True), _inp("time", "uint256", False)),
              "high", "Rocket Pool DAO proposal {proposalID} executed by {executor}", "RocketDAO"),
    EventSpec("ProposalAdded", "ProposalAdded(address,uint256,bytes,uint256)",
              _abi("ProposalAdded", _inp("proposer", "address", True), _inp("proposalID", "uint256", True), _inp("payload", "bytes", False), _inp("time", "uint256", False)),
              "medium", "Rocket Pool protocol DAO proposal {proposalID} added by {proposer}", "RocketDAO"),
    EventSpec("ProposalAdded", "ProposalAdded(address,string,uint256,bytes,uint256)",
              _abi("ProposalAdded", _inp("proposer", "address", True), _inp("proposalDAO", "string", True), _inp("proposalID", "uint256", True),
                   _inp("payload", "bytes", False), _inp("time", "uint256", False)),
              "medium", "Rocket Pool DAO proposal {proposalID} added by {proposer}", "RocketDAO"),
    EventSpec("ProposalDestroyed", "ProposalDestroyed(uint256,uint256)",
              _abi("ProposalDestroyed", _inp("proposalID", "uint256", True), _inp("time", "uint256", False)),
              "medium", "Rocket Pool protocol DAO proposal {proposalID} destroyed", "RocketDAO"),
    EventSpec("UpgradePending", "UpgradePending(uint256,bytes32,bytes32,uint256)",
              _abi("UpgradePending", _inp("upgradeProposalID", "uint256", False), _inp("upgradeType", "bytes32", True), _inp("name", "bytes32", True), _inp("time", "uint256", False)),
              "high", "Rocket Pool upgrade {upgradeProposalID} pending ({name})", "RocketDAO"),
    EventSpec("UpgradeVetoed", "UpgradeVetoed(uint256,uint256)",
              _abi("UpgradeVetoed", _inp("upgradeProposalID", "uint256", False), _inp("time", "uint256", False)),
              "medium", "Rocket Pool upgrade {upgradeProposalID} vetoed", "RocketDAO"),
    EventSpec("ContractUpgraded", "ContractUpgraded(bytes32,address,address,uint256)",
              _abi("ContractUpgraded", _inp("name", "bytes32", True), _inp("oldAddress", "address", True), _inp("newAddress", "address", True), _inp("time", "uint256", False)),
              "critical", "Rocket Pool contract {name} upgraded {oldAddress} -> {newAddress}", "RocketDAO"),
    EventSpec("ContractAdded", "ContractAdded(bytes32,address,uint256)",
              _abi("ContractAdded", _inp("name", "bytes32", True), _inp("newAddress", "address", True), _inp("time", "uint256", False)),
              "critical", "Rocket Pool contract {name} added at {newAddress}", "RocketDAO"),
    EventSpec("GuardianChanged", "GuardianChanged(address,address)",
              _abi("GuardianChanged", _inp("oldGuardian", "address", False), _inp("newGuardian", "address", False)),
              "critical", "RocketStorage guardian changed {oldGuardian} -> {newGuardian}", "RocketDAO"),
    # CoW Protocol solver allow-list (GPv2AllowListAuthentication).
    _single("SolverAdded", "address", "solver", False, "high", "solver added to the allow-list: {solver}", "GPv2AllowList"),
    _single("SolverRemoved", "address", "solver", False, "high", "solver removed from the allow-list: {solver}", "GPv2AllowList"),
    EventSpec("ManagerChanged", "ManagerChanged(address,address)",
              _abi("ManagerChanged", _inp("newManager", "address", False), _inp("oldManager", "address", False)),
              "critical", "allow-list manager changed {oldManager} -> {newManager}", "GPv2AllowList"),
    EventSpec("ProxyImplementationUpdated", "ProxyImplementationUpdated(address,address)",
              _abi("ProxyImplementationUpdated", _inp("previousImplementation", "address", True), _inp("newImplementation", "address", True)),
              "critical", "proxy implementation updated {previousImplementation} -> {newImplementation}", "EIP-173 proxy"),
    # Gearbox ACL.
    _single("PausableAdminAdded", "address", "newAdmin", True, "high", "pausable admin added: {newAdmin}", "GearboxACL"),
    _single("PausableAdminRemoved", "address", "admin", True, "high", "pausable admin removed: {admin}", "GearboxACL"),
    _single("UnpausableAdminAdded", "address", "newAdmin", True, "high", "unpausable admin added: {newAdmin}", "GearboxACL"),
    _single("UnpausableAdminRemoved", "address", "admin", True, "high", "unpausable admin removed: {admin}", "GearboxACL"),
    # 0x Settler deployer. Its ERC-721 Transfers only move a feature's token to the newest deployment, alongside
    # Deployed, so they are not watched.
    EventSpec("Deployed", "Deployed(uint128,uint32,address)",
              _abi("Deployed", _inp("feature", "uint128", True), _inp("nonce", "uint32", True), _inp("deployed", "address", True)),
              "critical", "new code deployed for feature {feature} (nonce {nonce}) at {deployed}", "SettlerDeployer"),
    EventSpec("Removed", "Removed(uint128,uint32,address)",
              _abi("Removed", _inp("feature", "uint128", True), _inp("nonce", "uint32", True), _inp("deployed", "address", True)),
              "high", "deployment {deployed} of feature {feature} (nonce {nonce}) removed", "SettlerDeployer"),
    _single("RemovedAll", "uint128", "feature", True, "high", "all deployments of feature {feature} removed", "SettlerDeployer"),
    EventSpec("Authorized", "Authorized(uint128,address,uint40)",
              _abi("Authorized", _inp("feature", "uint128", True), _inp("who", "address", True), _inp("deadline", "uint40", False)),
              "high", "{who} authorized to deploy feature {feature} until {deadline}", "SettlerDeployer"),
]

@dataclass(frozen=True)
class NoteSpec:
    """A DSNote call log: anonymous, topic0 is the function selector, topics 1-3 are msg.sender and the
    first two words of calldata, data carries msg.value and the full calldata."""
    name: str
    signature: str
    args: tuple[str, ...]
    severity: str
    describe: str
    source: str = "DSPause"


# Sky's governance pause: spells are plotted (scheduled), then exec'd after the delay.
NOTE_SPECS: dict[str, NoteSpec] = {}
for _n in [
    NoteSpec("SpellPlotted", "plot(address,bytes32,bytes,uint256)", ("usr", "tag", "fax", "eta"),
             "high", "spell {usr} plotted, executable from {eta_iso}"),
    NoteSpec("SpellExecuted", "exec(address,bytes32,bytes,uint256)", ("usr", "tag", "fax", "eta"), "high", "spell {usr} executed"),
    NoteSpec("SpellDropped", "drop(address,bytes32,bytes,uint256)", ("usr", "tag", "fax", "eta"), "medium", "spell {usr} dropped"),
    NoteSpec("PauseDelaySet", "setDelay(uint256)", ("delay",), "critical", "pause delay set to {delay}s"),
]:
    NOTE_SPECS["0x" + Web3.keccak(text=_n.signature).hex().removeprefix("0x")[:8] + "00" * 28] = _n

TRANSFER_SPEC = EventSpec(
    "Transfer", "Transfer(address,address,uint256)",
    _abi("Transfer", _inp("from", "address", True), _inp("to", "address", True), _inp("value", "uint256", False)),
    "high", "{amount} {symbol} sent from {from} to {to}", "ERC-20")


ERC721_TRANSFER_SPEC = EventSpec(
    "Transfer", "Transfer(address,address,uint256)",
    _abi("Transfer", _inp("from", "address", True), _inp("to", "address", True), _inp("tokenId", "uint256", True)),
    "high", "NFT #{tokenId} of {collection} sent from {from} to {to}", "ERC-721")

ERC1155_SINGLE_SPEC = EventSpec(
    "TransferSingle", "TransferSingle(address,address,address,uint256,uint256)",
    _abi("TransferSingle", _inp("operator", "address", True), _inp("from", "address", True), _inp("to", "address", True),
         _inp("id", "uint256", False), _inp("value", "uint256", False)),
    "high", "{value} of token #{id} of {collection} sent from {from} to {to}", "ERC-1155")

ERC1155_BATCH_SPEC = EventSpec(
    "TransferBatch", "TransferBatch(address,address,address,uint256[],uint256[])",
    _abi("TransferBatch", _inp("operator", "address", True), _inp("from", "address", True), _inp("to", "address", True),
         _inp("ids", "uint256[]", False), _inp("values", "uint256[]", False)),
    "high", "batch of {count} token ids of {collection} sent from {from} to {to}", "ERC-1155")


def topic0(signature: str) -> str:
    return Web3.keccak(text=signature).hex()


def _norm(t: str) -> str:
    return t if t.startswith("0x") else "0x" + t


BY_TOPIC: dict[str, EventSpec] = {_norm(topic0(s.signature)): s for s in CATALOG}
TRANSFER_TOPIC = _norm(topic0(TRANSFER_SPEC.signature))
ERC1155_TOPICS = [_norm(topic0(ERC1155_SINGLE_SPEC.signature)), _norm(topic0(ERC1155_BATCH_SPEC.signature))]
# Same signature as a CATALOG entry but a different `indexed` layout, so the same topic0 needs a second decoder.
VARIANTS: list[EventSpec] = [
    _single("ProposalExecuted", "uint256", "id", True, "high", "timelock proposal {id} executed", "EmergencyProtectedTimelock"),
]
VARIANTS_BY_TOPIC: dict[str, list[EventSpec]] = {}
for _v in VARIANTS:
    VARIANTS_BY_TOPIC.setdefault(_norm(topic0(_v.signature)), []).append(_v)
ADMIN_TOPICS: list[str] = list(BY_TOPIC.keys()) + list(NOTE_SPECS.keys())


def severity_rank(level: str) -> int:
    return SEVERITIES.index(level)
