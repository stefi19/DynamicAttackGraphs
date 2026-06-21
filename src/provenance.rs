use std::fmt;

use crate::schema::{
    AttackerCodeExecution, AttackerGoalReached, AttackerOwnsMachine, AttackerStartingPosition,
    AttackerTargetGoal, EffectiveNetworkAccess, FirewallRuleRecord, NetworkAccessRule,
    PrivilegeLevel, VulnerabilityRecord,
};

/// Canonical fact representation used by the explanation layer.
///
/// This is intentionally independent of Differential Dataflow internals:
/// explanations are reconstructed after computation from base facts and
/// derived fact sets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fact {
    VulExists {
        host: String,
        vulnerability_id: String,
        service: String,
        privilege: PrivilegeLevel,
    },
    Hacl {
        source: String,
        destination: String,
        service: String,
    },
    FirewallDeny {
        source: String,
        destination: String,
        service: String,
    },
    AttackerLocated {
        attacker_id: String,
        host: String,
        privilege: PrivilegeLevel,
    },
    AttackGoal {
        attacker_id: String,
        target: String,
    },
    EffectiveAccess {
        source: String,
        destination: String,
        service: String,
    },
    ExecCode {
        attacker_id: String,
        host: String,
        privilege: PrivilegeLevel,
    },
    OwnsMachine {
        attacker_id: String,
        host: String,
    },
    GoalReached {
        attacker_id: String,
        target: String,
    },
}

/// One rule application that derives a fact from zero or more premises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationStep {
    pub rule_name: String,
    pub premises: Vec<Fact>,
}

impl DerivationStep {
    pub fn new(rule_name: impl Into<String>, premises: Vec<Fact>) -> Self {
        Self {
            rule_name: rule_name.into(),
            premises,
        }
    }
}

/// A recursive proof tree for a target fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplanationTree {
    pub fact: Fact,
    pub derivation: Option<DerivationStep>,
    pub children: Vec<ExplanationTree>,
}

impl ExplanationTree {
    pub fn leaf(fact: Fact) -> Self {
        Self {
            fact,
            derivation: None,
            children: Vec::new(),
        }
    }

    pub fn derived(fact: Fact, derivation: DerivationStep, children: Vec<ExplanationTree>) -> Self {
        Self {
            fact,
            derivation: Some(derivation),
            children,
        }
    }
}

impl From<&VulnerabilityRecord> for Fact {
    fn from(record: &VulnerabilityRecord) -> Self {
        Fact::VulExists {
            host: record.host_name.clone(),
            vulnerability_id: record.vulnerability_id.clone(),
            service: record.affected_service.clone(),
            privilege: record.privilege_gained_on_exploit.clone(),
        }
    }
}

impl From<&NetworkAccessRule> for Fact {
    fn from(record: &NetworkAccessRule) -> Self {
        Fact::Hacl {
            source: record.source_host.clone(),
            destination: record.destination_host.clone(),
            service: record.service_name.clone(),
        }
    }
}

impl From<&FirewallRuleRecord> for Fact {
    fn from(record: &FirewallRuleRecord) -> Self {
        Fact::FirewallDeny {
            source: record.source_zone.clone(),
            destination: record.destination_host.clone(),
            service: record.service_name.clone(),
        }
    }
}

impl From<&AttackerStartingPosition> for Fact {
    fn from(record: &AttackerStartingPosition) -> Self {
        Fact::AttackerLocated {
            attacker_id: record.attacker_id.clone(),
            host: record.starting_host.clone(),
            privilege: record.initial_privilege.clone(),
        }
    }
}

impl From<&AttackerTargetGoal> for Fact {
    fn from(record: &AttackerTargetGoal) -> Self {
        Fact::AttackGoal {
            attacker_id: record.attacker_id.clone(),
            target: record.target_host_name.clone(),
        }
    }
}

impl From<&EffectiveNetworkAccess> for Fact {
    fn from(record: &EffectiveNetworkAccess) -> Self {
        Fact::EffectiveAccess {
            source: record.source_host.clone(),
            destination: record.destination_host.clone(),
            service: record.service_name.clone(),
        }
    }
}

impl From<&AttackerCodeExecution> for Fact {
    fn from(record: &AttackerCodeExecution) -> Self {
        Fact::ExecCode {
            attacker_id: record.attacker_id.clone(),
            host: record.compromised_host.clone(),
            privilege: record.obtained_privilege.clone(),
        }
    }
}

impl From<&AttackerOwnsMachine> for Fact {
    fn from(record: &AttackerOwnsMachine) -> Self {
        Fact::OwnsMachine {
            attacker_id: record.attacker_id.clone(),
            host: record.owned_host.clone(),
        }
    }
}

impl From<&AttackerGoalReached> for Fact {
    fn from(record: &AttackerGoalReached) -> Self {
        Fact::GoalReached {
            attacker_id: record.attacker_id.clone(),
            target: record.reached_target.clone(),
        }
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fact::VulExists {
                host,
                vulnerability_id,
                service,
                privilege,
            } => write!(
                formatter,
                "vulExists({host}, {vulnerability_id}, {service}, {privilege})"
            ),
            Fact::Hacl {
                source,
                destination,
                service,
            } => write!(formatter, "hacl({source}, {destination}, {service})"),
            Fact::FirewallDeny {
                source,
                destination,
                service,
            } => write!(
                formatter,
                "firewallDeny({source}, {destination}, {service})"
            ),
            Fact::AttackerLocated {
                attacker_id,
                host,
                privilege,
            } => write!(
                formatter,
                "attackerLocated({attacker_id}, {host}, {privilege})"
            ),
            Fact::AttackGoal {
                attacker_id,
                target,
            } => write!(formatter, "attackGoal({attacker_id}, {target})"),
            Fact::EffectiveAccess {
                source,
                destination,
                service,
            } => write!(
                formatter,
                "effectiveAccess({source}, {destination}, {service})"
            ),
            Fact::ExecCode {
                attacker_id,
                host,
                privilege,
            } => write!(formatter, "execCode({attacker_id}, {host}, {privilege})"),
            Fact::OwnsMachine { attacker_id, host } => {
                write!(formatter, "ownsMachine({attacker_id}, {host})")
            }
            Fact::GoalReached {
                attacker_id,
                target,
            } => write!(formatter, "goalReached({attacker_id}, {target})"),
        }
    }
}
