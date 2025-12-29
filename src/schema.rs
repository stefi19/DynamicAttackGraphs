// Schema for attack graph data types
// Defines all the structures needed to represent network security facts

use abomonation_derive::Abomonation;
use std::fmt;

// Type aliases for better readability
pub type HostIdentifier = String;
pub type ServiceName = String;
pub type VulnerabilityIdentifier = String;
pub type AttackerIdentifier = String;

// Privilege levels that can be obtained on a system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub enum PrivilegeLevel {
    None,
    User,
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

// What a firewall rule does
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub enum FirewallRuleAction {
    Allow,
    Deny,
}

// ----------------------------------
// Base facts (input data)
// ----------------------------------

// A vulnerability that exists on a specific host
// Similar to MulVAL's vulExists predicate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct VulnerabilityRecord {
    pub host_name: HostIdentifier,
    pub vulnerability_id: VulnerabilityIdentifier,
    pub affected_service: ServiceName,
    pub privilege_gained_on_exploit: PrivilegeLevel,
}

impl VulnerabilityRecord {
    pub fn new(host_name: &str, vulnerability_id: &str, affected_service: &str, privilege_gained: PrivilegeLevel) -> Self {
        Self {
            host_name: host_name.to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            affected_service: affected_service.to_string(),
            privilege_gained_on_exploit: privilege_gained,
        }
    }
}

// Network connection between two hosts
// Similar to MulVAL's hacl predicate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct NetworkAccessRule {
    pub source_host: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
}

impl NetworkAccessRule {
    pub fn new(source: &str, destination: &str, service: &str) -> Self {
        Self {
            source_host: source.to_string(),
            destination_host: destination.to_string(),
            service_name: service.to_string(),
        }
    }
}

// A firewall rule that blocks or allows traffic
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct FirewallRuleRecord {
    pub source_zone: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
    pub rule_action: FirewallRuleAction,
}

impl FirewallRuleRecord {
    pub fn create_deny_rule(source: &str, destination: &str, service: &str) -> Self {
        Self {
            source_zone: source.to_string(),
            destination_host: destination.to_string(),
            service_name: service.to_string(),
            rule_action: FirewallRuleAction::Deny,
        }
    }
}

// Where the attacker starts from
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
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

// What the attacker wants to compromise
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
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

// ----------------------------------
// Derived facts (computed by rules)
// ----------------------------------

// Network access after applying firewall rules
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct EffectiveNetworkAccess {
    pub source_host: HostIdentifier,
    pub destination_host: HostIdentifier,
    pub service_name: ServiceName,
}

// Attacker can execute code on a host
// Similar to MulVAL's execCode predicate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct AttackerCodeExecution {
    pub attacker_id: AttackerIdentifier,
    pub compromised_host: HostIdentifier,
    pub obtained_privilege: PrivilegeLevel,
}

impl fmt::Display for AttackerCodeExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "execCode({}, {}, {})", self.attacker_id, self.compromised_host, self.obtained_privilege)
    }
}

// Attacker has full control of a machine (root access)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct AttackerOwnsMachine {
    pub attacker_id: AttackerIdentifier,
    pub owned_host: HostIdentifier,
}

impl fmt::Display for AttackerOwnsMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ownsMachine({}, {})", self.attacker_id, self.owned_host)
    }
}

// Attacker has reached their target
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct AttackerGoalReached {
    pub attacker_id: AttackerIdentifier,
    pub reached_target: HostIdentifier,
}

impl fmt::Display for AttackerGoalReached {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "goalReached({}, {})", self.attacker_id, self.reached_target)
    }
}

// ----------------------------------
// Key types for join operations
// ----------------------------------

pub type AttackerAndHostKey = (AttackerIdentifier, HostIdentifier);
pub type NetworkAccessKey = (HostIdentifier, HostIdentifier, ServiceName);
pub type HostAndServiceKey = (HostIdentifier, ServiceName);
