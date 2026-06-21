use std::collections::HashSet;
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

/// Base input relations available to the explainer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceBaseFacts {
    pub vulnerabilities: Vec<VulnerabilityRecord>,
    pub network_access: Vec<NetworkAccessRule>,
    pub firewall_rules: Vec<FirewallRuleRecord>,
    pub attacker_positions: Vec<AttackerStartingPosition>,
    pub attacker_goals: Vec<AttackerTargetGoal>,
}

impl ProvenanceBaseFacts {
    fn as_fact_set(&self) -> HashSet<Fact> {
        let mut facts = HashSet::new();

        facts.extend(self.vulnerabilities.iter().map(Fact::from));
        facts.extend(self.network_access.iter().map(Fact::from));
        facts.extend(self.firewall_rules.iter().map(Fact::from));
        facts.extend(self.attacker_positions.iter().map(Fact::from));
        facts.extend(self.attacker_goals.iter().map(Fact::from));

        facts
    }
}

/// Derived relations available to the explainer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceDerivedFacts {
    pub effective_network_access: Vec<EffectiveNetworkAccess>,
    pub code_executions: Vec<AttackerCodeExecution>,
    pub machines_owned: Vec<AttackerOwnsMachine>,
    pub goals_reached: Vec<AttackerGoalReached>,
}

impl ProvenanceDerivedFacts {
    fn as_fact_set(&self) -> HashSet<Fact> {
        let mut facts = HashSet::new();

        facts.extend(self.effective_network_access.iter().map(Fact::from));
        facts.extend(self.code_executions.iter().map(Fact::from));
        facts.extend(self.machines_owned.iter().map(Fact::from));
        facts.extend(self.goals_reached.iter().map(Fact::from));

        facts
    }
}

/// Reconstructs one valid explanation tree from final base and derived facts.
///
/// The current implementation is deliberately small: it does not enumerate all
/// possible proofs, and it does not store provenance inside Differential
/// Dataflow. Instead, it searches the final relations for premises that satisfy
/// the attack graph rules.
#[derive(Debug, Clone)]
pub struct Explainer {
    base_facts: HashSet<Fact>,
    derived_facts: HashSet<Fact>,
}

impl Explainer {
    pub fn new(base_facts: ProvenanceBaseFacts, derived_facts: ProvenanceDerivedFacts) -> Self {
        Self {
            base_facts: base_facts.as_fact_set(),
            derived_facts: derived_facts.as_fact_set(),
        }
    }

    pub fn explain(&self, target: &Fact) -> Option<ExplanationTree> {
        let mut visiting = HashSet::new();
        self.explain_fact(target, &mut visiting)
    }

    fn explain_fact(&self, target: &Fact, visiting: &mut HashSet<Fact>) -> Option<ExplanationTree> {
        if self.base_facts.contains(target) {
            return Some(ExplanationTree::leaf(target.clone()));
        }

        if !self.derived_facts.contains(target) || !visiting.insert(target.clone()) {
            return None;
        }

        let explanation = match target {
            Fact::GoalReached {
                attacker_id,
                target,
            } => self.explain_goal_reached(attacker_id, target, visiting),
            Fact::OwnsMachine { attacker_id, host } => {
                self.explain_owns_machine(attacker_id, host, visiting)
            }
            Fact::ExecCode {
                attacker_id,
                host,
                privilege,
            } => self.explain_exec_code(attacker_id, host, privilege, visiting),
            Fact::EffectiveAccess {
                source,
                destination,
                service,
            } => self.explain_effective_access(source, destination, service),
            _ => None,
        };

        visiting.remove(target);
        explanation
    }

    fn explain_goal_reached(
        &self,
        attacker_id: &str,
        target: &str,
        visiting: &mut HashSet<Fact>,
    ) -> Option<ExplanationTree> {
        let target_fact = Fact::GoalReached {
            attacker_id: attacker_id.to_string(),
            target: target.to_string(),
        };
        let goal_fact = Fact::AttackGoal {
            attacker_id: attacker_id.to_string(),
            target: target.to_string(),
        };
        let owns_fact = Fact::OwnsMachine {
            attacker_id: attacker_id.to_string(),
            host: target.to_string(),
        };

        let goal_tree = self.explain_fact(&goal_fact, visiting)?;
        let owns_tree = self.explain_fact(&owns_fact, visiting)?;
        let premises = vec![goal_fact, owns_fact];

        Some(ExplanationTree::derived(
            target_fact,
            DerivationStep::new("goal_reached_from_goal_and_ownership", premises),
            vec![goal_tree, owns_tree],
        ))
    }

    fn explain_owns_machine(
        &self,
        attacker_id: &str,
        host: &str,
        visiting: &mut HashSet<Fact>,
    ) -> Option<ExplanationTree> {
        let target_fact = Fact::OwnsMachine {
            attacker_id: attacker_id.to_string(),
            host: host.to_string(),
        };
        let root_exec_fact = Fact::ExecCode {
            attacker_id: attacker_id.to_string(),
            host: host.to_string(),
            privilege: PrivilegeLevel::Root,
        };

        let root_exec_tree = self.explain_fact(&root_exec_fact, visiting)?;

        Some(ExplanationTree::derived(
            target_fact,
            DerivationStep::new("ownership_from_root_exec_code", vec![root_exec_fact]),
            vec![root_exec_tree],
        ))
    }

    fn explain_exec_code(
        &self,
        attacker_id: &str,
        host: &str,
        privilege: &PrivilegeLevel,
        visiting: &mut HashSet<Fact>,
    ) -> Option<ExplanationTree> {
        let target_fact = Fact::ExecCode {
            attacker_id: attacker_id.to_string(),
            host: host.to_string(),
            privilege: privilege.clone(),
        };
        let starting_fact = Fact::AttackerLocated {
            attacker_id: attacker_id.to_string(),
            host: host.to_string(),
            privilege: privilege.clone(),
        };

        if self.base_facts.contains(&starting_fact) {
            return Some(ExplanationTree::derived(
                target_fact,
                DerivationStep::new(
                    "initial_exec_code_from_attacker_location",
                    vec![starting_fact.clone()],
                ),
                vec![ExplanationTree::leaf(starting_fact)],
            ));
        }

        let mut vulnerabilities = self
            .base_facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::VulExists {
                    host: vuln_host,
                    vulnerability_id,
                    service,
                    privilege: vuln_privilege,
                } if vuln_host == host && vuln_privilege == privilege => {
                    Some((vulnerability_id, service))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        vulnerabilities.sort();

        for (vulnerability_id, service) in vulnerabilities {
            let vuln_fact = Fact::VulExists {
                host: host.to_string(),
                vulnerability_id: vulnerability_id.clone(),
                service: service.clone(),
                privilege: privilege.clone(),
            };

            let mut accesses = self
                .derived_facts
                .iter()
                .filter_map(|fact| match fact {
                    Fact::EffectiveAccess {
                        source,
                        destination,
                        service: access_service,
                    } if destination == host && access_service == service => {
                        Some((source.clone(), access_service.clone()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            accesses.sort();

            for (source, access_service) in accesses {
                let access_fact = Fact::EffectiveAccess {
                    source: source.clone(),
                    destination: host.to_string(),
                    service: access_service,
                };

                let mut previous_exec_facts = self
                    .derived_facts
                    .iter()
                    .filter_map(|fact| match fact {
                        Fact::ExecCode {
                            attacker_id: exec_attacker_id,
                            host: exec_host,
                            privilege: exec_privilege,
                        } if exec_attacker_id == attacker_id && exec_host == &source => {
                            Some(Fact::ExecCode {
                                attacker_id: exec_attacker_id.clone(),
                                host: exec_host.clone(),
                                privilege: exec_privilege.clone(),
                            })
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                previous_exec_facts.sort();

                for previous_exec_fact in previous_exec_facts {
                    let previous_exec_tree = self.explain_fact(&previous_exec_fact, visiting)?;
                    let access_tree = self.explain_fact(&access_fact, visiting)?;
                    let vulnerability_tree = self.explain_fact(&vuln_fact, visiting)?;
                    let premises = vec![previous_exec_fact, access_fact, vuln_fact];

                    return Some(ExplanationTree::derived(
                        target_fact,
                        DerivationStep::new(
                            "exec_code_from_network_reachability_and_vulnerability",
                            premises,
                        ),
                        vec![previous_exec_tree, access_tree, vulnerability_tree],
                    ));
                }
            }
        }

        None
    }

    fn explain_effective_access(
        &self,
        source: &str,
        destination: &str,
        service: &str,
    ) -> Option<ExplanationTree> {
        let target_fact = Fact::EffectiveAccess {
            source: source.to_string(),
            destination: destination.to_string(),
            service: service.to_string(),
        };
        let network_fact = Fact::Hacl {
            source: source.to_string(),
            destination: destination.to_string(),
            service: service.to_string(),
        };
        let deny_fact = Fact::FirewallDeny {
            source: source.to_string(),
            destination: destination.to_string(),
            service: service.to_string(),
        };

        if !self.base_facts.contains(&network_fact) || self.base_facts.contains(&deny_fact) {
            return None;
        }

        Some(ExplanationTree::derived(
            target_fact,
            DerivationStep::new(
                "effective_access_from_hacl_without_firewall_deny",
                vec![network_fact.clone()],
            ),
            vec![ExplanationTree::leaf(network_fact)],
        ))
    }
}
