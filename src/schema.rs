//! Dynamic Attack Graphs using Differential Dataflow
//!
//! This module defines the core data types (schema) for representing
//! network security concepts in a way compatible with differential dataflow.

use abomonation_derive::Abomonation;
use std::fmt;

/// Represents a host/machine in the network
pub type Host = String;

/// Represents a network service/protocol
pub type Service = String;

/// Represents a CVE identifier
pub type CveId = String;

/// Represents an attacker identity
pub type AttackerId = String;

/// Privilege level on a system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub enum Privilege {
    None,
    User,
    Root,
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Privilege::None => write!(f, "none"),
            Privilege::User => write!(f, "user"),
            Privilege::Root => write!(f, "root"),
        }
    }
}

/// Firewall action
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub enum FirewallAction {
    Allow,
    Deny,
}

// ============================================================================
// BASE FACTS (EDB - Extensional Database)
// ============================================================================

/// A vulnerability present on a host
/// 
/// Corresponds to MulVAL's vulExists(Host, VulnID, Service)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct Vulnerability {
    /// The host where the vulnerability exists
    pub host: Host,
    /// CVE identifier
    pub cve_id: CveId,
    /// The service/protocol affected
    pub service: Service,
    /// What privilege level the exploit grants
    pub grants_privilege: Privilege,
}

impl Vulnerability {
    pub fn new(host: &str, cve_id: &str, service: &str, grants: Privilege) -> Self {
        Self {
            host: host.to_string(),
            cve_id: cve_id.to_string(),
            service: service.to_string(),
            grants_privilege: grants,
        }
    }
}

/// Network connectivity between hosts
/// 
/// Corresponds to MulVAL's hacl(SrcHost, DstHost, Protocol, Port)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct NetworkAccess {
    /// Source host
    pub src_host: Host,
    /// Destination host
    pub dst_host: Host,
    /// Service/protocol accessible
    pub service: Service,
}

impl NetworkAccess {
    pub fn new(src: &str, dst: &str, service: &str) -> Self {
        Self {
            src_host: src.to_string(),
            dst_host: dst.to_string(),
            service: service.to_string(),
        }
    }
}

/// Firewall rule
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct FirewallRule {
    /// Source host or zone
    pub src: Host,
    /// Destination host
    pub dst: Host,
    /// Service affected
    pub service: Service,
    /// Action (allow/deny)
    pub action: FirewallAction,
}

impl FirewallRule {
    pub fn deny(src: &str, dst: &str, service: &str) -> Self {
        Self {
            src: src.to_string(),
            dst: dst.to_string(),
            service: service.to_string(),
            action: FirewallAction::Deny,
        }
    }
}

/// Where an attacker is initially located
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct AttackerLocation {
    /// Attacker identifier
    pub attacker: AttackerId,
    /// Initial host where attacker has access
    pub host: Host,
    /// Initial privilege level
    pub privilege: Privilege,
}

impl AttackerLocation {
    pub fn new(attacker: &str, host: &str, privilege: Privilege) -> Self {
        Self {
            attacker: attacker.to_string(),
            host: host.to_string(),
            privilege,
        }
    }
}

/// What the attacker wants to compromise
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct AttackerGoal {
    /// Attacker identifier
    pub attacker: AttackerId,
    /// Target host
    pub target_host: Host,
}

impl AttackerGoal {
    pub fn new(attacker: &str, target: &str) -> Self {
        Self {
            attacker: attacker.to_string(),
            target_host: target.to_string(),
        }
    }
}

// ============================================================================
// DERIVED FACTS (IDB - Intensional Database)
// ============================================================================

/// Effective network access (after firewall rules applied)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct EffectiveAccess {
    pub src_host: Host,
    pub dst_host: Host,
    pub service: Service,
}

/// Attacker has gained code execution on a host
/// 
/// Corresponds to MulVAL's execCode(Attacker, Host, Privilege)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct ExecCode {
    pub attacker: AttackerId,
    pub host: Host,
    pub privilege: Privilege,
}

impl fmt::Display for ExecCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "execCode({}, {}, {})", self.attacker, self.host, self.privilege)
    }
}

/// Attacker owns/controls a machine (has root)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct OwnsMachine {
    pub attacker: AttackerId,
    pub host: Host,
}

impl fmt::Display for OwnsMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ownsMachine({}, {})", self.attacker, self.host)
    }
}

/// Attacker has reached their goal
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Abomonation)]
pub struct GoalReached {
    pub attacker: AttackerId,
    pub target: Host,
}

impl fmt::Display for GoalReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "goalReached({}, {})", self.attacker, self.target)
    }
}

// ============================================================================
// HELPER TYPES FOR JOINS
// ============================================================================

/// Key for joining on (attacker, host) pairs
pub type AttackerHostKey = (AttackerId, Host);

/// Key for joining on (src, dst, service) triples
pub type AccessKey = (Host, Host, Service);

/// Key for joining on (host, service) pairs  
pub type HostServiceKey = (Host, Service);
