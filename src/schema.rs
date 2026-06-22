// ================================================================
// schema.rs
//
// This module contains all data types (the "schema") used by the
// Dynamic Attack Graphs project.  The types represent both input
// facts (vulnerabilities, network rules, firewall rules, attacker
// start/goal) and derived facts (effective access, compromises,
// ownership, goal reached).  These types are passed through
// differential-dataflow collections and therefore need to be
// cheaply serializable / comparable / hashable.
// ================================================================

use abomonation_derive::Abomonation; // fast binary (de)serialization
use serde::{Deserialize, Serialize};
use std::fmt;

// ----------------------------------------------------------------
// Type aliases
// ----------------------------------------------------------------
pub type HostIdentifier = String; // e.g. "webserver-1"
pub type ServiceName = String; // e.g. "ssh", "http"
pub type VulnerabilityIdentifier = String; // e.g. "CVE-2024-12345"
pub type AttackerIdentifier = String; // e.g. "internet", "attacker-1"

// ----------------------------------------------------------------
// Privilege levels
// ----------------------------------------------------------------
// Represents the privilege an attacker gains when exploiting a
// vulnerability.  We implement `Display` for nicer logs.  We derive
// the standard traits used by differential-dataflow: ordering,
// hashing, cloning, and `Abomonation` for fast transfers between
// workers.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub enum PrivilegeLevel {
    // No privilege gained (placeholder; may be unused in practice)
    None,
    // Regular user privileges (low-level access)
    User,
    // Administrator / root privileges (full control)
    Root,
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivilegeLevel::None => write!(formatter, "none"),
            PrivilegeLevel::User => write!(formatter, "user"),
            PrivilegeLevel::Root => write!(formatter, "root"),
        }
    }
}

// ----------------------------------------------------------------
// Firewall rule action
// ----------------------------------------------------------------
// Simple enum to represent whether a firewall rule allows or denies
// traffic.  When building `EffectiveNetworkAccess` we will remove
// any NetworkAccess entries that match a `Deny` rule using an
// anti-join.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub enum FirewallRuleAction {
    Allow,
    Deny,
}

// ----------------------------------------------------------------
// Base facts (inputs)
// ----------------------------------------------------------------
// The following structs model the raw facts that are inserted into
// the system by scanners, configuration, or operator inputs.  They
// correspond closely to predicates in MulVAL-style Datalog (e.g.
// `vulExists`, `hacl`, `attackerLocated`).

// A vulnerability observed on a host.  This maps to
// `vulExists(Host, CVE, Service, Priv)` in the MulVAL notation used
// in the paper.  The struct fields are public because they are used
// directly in differential-dataflow mapping and joining operations.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct VulnerabilityRecord {
    // Host that has the vulnerability
    pub host_name: HostIdentifier,
    // The vulnerability identifier (CVE or internal tracker)
    pub vulnerability_id: VulnerabilityIdentifier,
    // Network service affected by this vulnerability (e.g. "ssh")
    pub affected_service: ServiceName,
    // The privilege level the attacker obtains when exploiting
    pub privilege_gained_on_exploit: PrivilegeLevel,
}

impl VulnerabilityRecord {
    // Convenience constructor to avoid repeated `.to_string()` calls
    // at call sites.  This keeps tests and examples concise.
    pub fn new(
        host_name: &str,
        vulnerability_id: &str,
        affected_service: &str,
        privilege_gained: PrivilegeLevel,
    ) -> Self {
        Self {
            host_name: host_name.to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            affected_service: affected_service.to_string(),
            privilege_gained_on_exploit: privilege_gained,
        }
    }
}

// A local privilege escalation vulnerability observed on a host.
// This maps to `localVulExists(Host, CVE, Priv)` and is exploitable
// only after an attacker already has non-root code execution on Host.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct LocalVulnerabilityRecord {
    pub host_name: HostIdentifier,
    pub vulnerability_id: VulnerabilityIdentifier,
    pub privilege_gained_on_exploit: PrivilegeLevel,
}

impl LocalVulnerabilityRecord {
    pub fn new(host_name: &str, vulnerability_id: &str, privilege_gained: PrivilegeLevel) -> Self {
        Self {
            host_name: host_name.to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            privilege_gained_on_exploit: privilege_gained,
        }
    }
}

// Network connectivity / access rule.  This represents that traffic
// from `source_host` can reach `destination_host` on `service_name`.
// In MulVAL this would be `hacl(Src, Dst, Service)`.  Note that the
// presence of a NetworkAccessRule does not mean traffic is actually
// allowed - firewall rules can block it.  Effective access is
// computed later by combining these facts with firewall rules.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct NetworkAccessRule {
    pub source_host: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
}

impl NetworkAccessRule {
    // Small helper constructor; used by examples and tests to keep
    // call sites readable.
    pub fn new(source: &str, destination: &str, service: &str) -> Self {
        Self {
            source_host: source.to_string(),
            destination_host: destination.to_string(),
            service_name: service.to_string(),
        }
    }
}

// Firewall rule record.  This models explicit allow/deny rules in an
// ACL or firewall.  The `rule_action` field controls whether traffic
// is permitted.  When composing the dataflow we will typically
// transform `FirewallRuleRecord` into a keyed collection of denies
// to be antijoined against the network rules (i.e. remove any
// network edges that are explicitly denied).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct FirewallRuleRecord {
    // The origin or zone that the rule applies to (could be an IP,
    // a host name, or a logical zone name).  We use HostIdentifier
    // for simplicity in the PoC.
    pub source_zone: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
    pub rule_action: FirewallRuleAction,
}

impl FirewallRuleRecord {
    // Helper to create a deny rule quickly in examples/benchmarks.
    pub fn create_deny_rule(source: &str, destination: &str, service: &str) -> Self {
        Self {
            source_zone: source.to_string(),
            destination_host: destination.to_string(),
            service_name: service.to_string(),
            rule_action: FirewallRuleAction::Deny,
        }
    }
}

// Attacker's initial / starting position.  This corresponds to the
// MulVAL `attackerLocated` fact and includes the initial privilege
// the attacker already possesses (for example, an inside attacker
// might already have 'User' privileges on a host).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct AttackerStartingPosition {
    pub attacker_id: AttackerIdentifier,
    pub starting_host: HostIdentifier,
    pub initial_privilege: PrivilegeLevel,
}

impl AttackerStartingPosition {
    pub fn new(attacker_id: &str, starting_host: &str, initial_privilege: PrivilegeLevel) -> Self {
        Self {
            attacker_id: attacker_id.to_string(),
            starting_host: starting_host.to_string(),
            initial_privilege,
        }
    }
}

// The attacker's goal: which host they wish to compromise.  This is
// used by the evaluation to check whether a target was reached.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct AttackerTargetGoal {
    pub attacker_id: AttackerIdentifier,
    pub target_host_name: HostIdentifier,
}

impl AttackerTargetGoal {
    pub fn new(attacker_id: &str, target_host: &str) -> Self {
        Self {
            attacker_id: attacker_id.to_string(),
            target_host_name: target_host.to_string(),
        }
    }
}

// ----------------------------------------------------------------
// Derived facts (outputs of the dataflow)
// ----------------------------------------------------------------
// These structs represent derived/derived facts that the dataflow
// computes from the base facts using joins, antijoins and iteration.

// Effective network access represents the network edges that are
// actually usable by an attacker after applying firewall denies.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct EffectiveNetworkAccess {
    pub source_host: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
}

// execCode: attacker can execute code on host with some privilege.
// This is the central derived predicate of MulVAL-style analysis.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct AttackerCodeExecution {
    pub attacker_id: AttackerIdentifier,
    pub compromised_host: HostIdentifier,
    pub obtained_privilege: PrivilegeLevel,
}

impl fmt::Display for AttackerCodeExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Nice human-readable printing for logs and debugging
        write!(
            formatter,
            "execCode({}, {}, {})",
            self.attacker_id, self.compromised_host, self.obtained_privilege
        )
    }
}

// ownsMachine: a convenience derived fact when the attacker has
// Root on a host.  Useful for goal checking and for generating
// alerts in examples.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct AttackerOwnsMachine {
    pub attacker_id: AttackerIdentifier,
    pub owned_host: HostIdentifier,
}

impl fmt::Display for AttackerOwnsMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ownsMachine({}, {})",
            self.attacker_id, self.owned_host
        )
    }
}

// goalReached: indicates the attacker successfully reached their
// declared goal.  This is computed by semijoining the goal list with
// the set of owned machines.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation, Serialize, Deserialize,
)]
pub struct AttackerGoalReached {
    pub attacker_id: AttackerIdentifier,
    pub reached_target: HostIdentifier,
}

impl fmt::Display for AttackerGoalReached {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "goalReached({}, {})",
            self.attacker_id, self.reached_target
        )
    }
}

// ----------------------------------------------------------------
// Key types for joins
// ----------------------------------------------------------------
// These tuple aliases document the shapes used when creating keyed
// collections for joins and semijoins inside the dataflow.  Using
// aliases reduces duplication and clarifies intent at join sites.
pub type AttackerAndHostKey = (AttackerIdentifier, HostIdentifier);
pub type NetworkAccessKey = (HostIdentifier, HostIdentifier, ServiceName);
pub type HostAndServiceKey = (HostIdentifier, ServiceName);
