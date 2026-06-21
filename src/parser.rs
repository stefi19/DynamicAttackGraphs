use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::schema::{
    AttackerStartingPosition, AttackerTargetGoal, FirewallRuleRecord, LocalVulnerabilityRecord,
    NetworkAccessRule, PrivilegeLevel, VulnerabilityRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFact {
    VulExists(VulnerabilityRecord),
    LocalVulExists(LocalVulnerabilityRecord),
    Hacl(NetworkAccessRule),
    FirewallDeny(FirewallRuleRecord),
    AttackerLocated(AttackerStartingPosition),
    AttackGoal(AttackerTargetGoal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputUpdate {
    Insert(InputFact),
    Remove(InputFact),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputScenario {
    pub vulnerabilities: Vec<VulnerabilityRecord>,
    pub local_vulnerabilities: Vec<LocalVulnerabilityRecord>,
    pub network_access: Vec<NetworkAccessRule>,
    pub firewall_rules: Vec<FirewallRuleRecord>,
    pub attacker_positions: Vec<AttackerStartingPosition>,
    pub attacker_goals: Vec<AttackerTargetGoal>,
}

impl InputScenario {
    pub fn push_fact(&mut self, fact: InputFact) {
        match fact {
            InputFact::VulExists(vulnerability) => {
                self.vulnerabilities.push(vulnerability);
            }
            InputFact::LocalVulExists(vulnerability) => {
                self.local_vulnerabilities.push(vulnerability);
            }
            InputFact::Hacl(network_access) => {
                self.network_access.push(network_access);
            }
            InputFact::FirewallDeny(firewall_rule) => {
                self.firewall_rules.push(firewall_rule);
            }
            InputFact::AttackerLocated(attacker_position) => {
                self.attacker_positions.push(attacker_position);
            }
            InputFact::AttackGoal(attacker_goal) => {
                self.attacker_goals.push(attacker_goal);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingPeriod,
    MalformedFact(String),
    UnknownPredicate(String),
    InvalidArity {
        predicate: String,
        expected: usize,
        found: usize,
    },
    InvalidPrivilege(String),
    Io {
        path: PathBuf,
        message: String,
    },
    Line {
        line_number: usize,
        source: Box<ParseError>,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingPeriod => write!(formatter, "fact must end with a period"),
            ParseError::MalformedFact(line) => write!(formatter, "malformed fact: {line}"),
            ParseError::UnknownPredicate(predicate) => {
                write!(formatter, "unknown predicate: {predicate}")
            }
            ParseError::InvalidArity {
                predicate,
                expected,
                found,
            } => write!(
                formatter,
                "predicate {predicate} expects {expected} arguments, found {found}"
            ),
            ParseError::InvalidPrivilege(privilege) => {
                write!(formatter, "invalid privilege value: {privilege}")
            }
            ParseError::Io { path, message } => {
                write!(formatter, "failed to read {}: {message}", path.display())
            }
            ParseError::Line {
                line_number,
                source,
            } => {
                write!(formatter, "line {line_number}: {source}")
            }
        }
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParseError::Line { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn parse_fact_line(line: &str) -> Result<Option<InputFact>, ParseError> {
    let trimmed = line.trim();

    if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
        return Ok(None);
    }

    if !trimmed.ends_with('.') {
        return Err(ParseError::MissingPeriod);
    }

    let fact_body = trimmed[..trimmed.len() - 1].trim();
    let open_paren = fact_body
        .find('(')
        .ok_or_else(|| ParseError::MalformedFact(trimmed.to_string()))?;
    let close_paren = fact_body
        .rfind(')')
        .ok_or_else(|| ParseError::MalformedFact(trimmed.to_string()))?;

    if close_paren < open_paren || !fact_body[close_paren + 1..].trim().is_empty() {
        return Err(ParseError::MalformedFact(trimmed.to_string()));
    }

    let predicate = fact_body[..open_paren].trim();
    let arguments = parse_arguments(&fact_body[open_paren + 1..close_paren])?;

    match predicate {
        "vulExists" => {
            require_arity(predicate, &arguments, 4)?;
            Ok(Some(InputFact::VulExists(VulnerabilityRecord::new(
                &arguments[0],
                &arguments[1],
                &arguments[2],
                parse_privilege(&arguments[3])?,
            ))))
        }
        "localVulExists" => {
            require_arity(predicate, &arguments, 3)?;
            Ok(Some(InputFact::LocalVulExists(
                LocalVulnerabilityRecord::new(
                    &arguments[0],
                    &arguments[1],
                    parse_privilege(&arguments[2])?,
                ),
            )))
        }
        "hacl" => {
            require_arity(predicate, &arguments, 3)?;
            Ok(Some(InputFact::Hacl(NetworkAccessRule::new(
                &arguments[0],
                &arguments[1],
                &arguments[2],
            ))))
        }
        "firewallDeny" => {
            require_arity(predicate, &arguments, 3)?;
            Ok(Some(InputFact::FirewallDeny(
                FirewallRuleRecord::create_deny_rule(&arguments[0], &arguments[1], &arguments[2]),
            )))
        }
        "attackerLocated" => {
            require_arity(predicate, &arguments, 3)?;
            Ok(Some(InputFact::AttackerLocated(
                AttackerStartingPosition::new(
                    &arguments[0],
                    &arguments[1],
                    parse_privilege(&arguments[2])?,
                ),
            )))
        }
        "attackGoal" => {
            require_arity(predicate, &arguments, 2)?;
            Ok(Some(InputFact::AttackGoal(AttackerTargetGoal::new(
                &arguments[0],
                &arguments[1],
            ))))
        }
        _ => Err(ParseError::UnknownPredicate(predicate.to_string())),
    }
}

pub fn parse_facts_file(path: &Path) -> Result<InputScenario, ParseError> {
    let contents = fs::read_to_string(path).map_err(|error| ParseError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;

    let mut scenario = InputScenario::default();

    for (line_index, line) in contents.lines().enumerate() {
        if let Some(fact) = parse_fact_line(line).map_err(|source| ParseError::Line {
            line_number: line_index + 1,
            source: Box::new(source),
        })? {
            scenario.push_fact(fact);
        }
    }

    Ok(scenario)
}

pub fn parse_update_line(line: &str) -> Result<Option<InputUpdate>, ParseError> {
    let trimmed = line.trim();

    if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
        return Ok(None);
    }

    if !trimmed.ends_with('.') {
        return Err(ParseError::MissingPeriod);
    }

    let body = trimmed[..trimmed.len() - 1].trim();
    if body.starts_with("remove(") && body.ends_with(')') {
        let inner_fact = body["remove(".len()..body.len() - 1].trim();
        let fact_line = format!("{inner_fact}.");
        return parse_fact_line(&fact_line).map(|fact| fact.map(InputUpdate::Remove));
    }

    parse_fact_line(trimmed).map(|fact| fact.map(InputUpdate::Insert))
}

pub fn parse_update_file(path: &Path) -> Result<Vec<InputUpdate>, ParseError> {
    let contents = fs::read_to_string(path).map_err(|error| ParseError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;

    let mut updates = Vec::new();

    for (line_index, line) in contents.lines().enumerate() {
        if let Some(update) = parse_update_line(line).map_err(|source| ParseError::Line {
            line_number: line_index + 1,
            source: Box::new(source),
        })? {
            updates.push(update);
        }
    }

    Ok(updates)
}

fn parse_arguments(arguments: &str) -> Result<Vec<String>, ParseError> {
    let parsed_arguments: Vec<_> = arguments
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect();

    if parsed_arguments.iter().any(String::is_empty) {
        return Err(ParseError::MalformedFact(arguments.to_string()));
    }

    Ok(parsed_arguments)
}

fn require_arity(predicate: &str, arguments: &[String], expected: usize) -> Result<(), ParseError> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidArity {
            predicate: predicate.to_string(),
            expected,
            found: arguments.len(),
        })
    }
}

fn parse_privilege(privilege: &str) -> Result<PrivilegeLevel, ParseError> {
    match privilege {
        "none" => Ok(PrivilegeLevel::None),
        "user" => Ok(PrivilegeLevel::User),
        "root" => Ok(PrivilegeLevel::Root),
        _ => Err(ParseError::InvalidPrivilege(privilege.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_facts_with_whitespace() {
        assert_eq!(
            parse_fact_line(" vulExists( web01 , cve_2024_1234 , http , user ). "),
            Ok(Some(InputFact::VulExists(VulnerabilityRecord::new(
                "web01",
                "cve_2024_1234",
                "http",
                PrivilegeLevel::User
            ))))
        );
        assert_eq!(
            parse_fact_line("hacl(internet, web01, https)."),
            Ok(Some(InputFact::Hacl(NetworkAccessRule::new(
                "internet", "web01", "https"
            ))))
        );
        assert_eq!(
            parse_fact_line("localVulExists(web01, cve_2024_local, root)."),
            Ok(Some(InputFact::LocalVulExists(
                LocalVulnerabilityRecord::new("web01", "cve_2024_local", PrivilegeLevel::Root)
            )))
        );
        assert_eq!(
            parse_fact_line("firewallDeny(internet, web01, http)."),
            Ok(Some(InputFact::FirewallDeny(
                FirewallRuleRecord::create_deny_rule("internet", "web01", "http")
            )))
        );
        assert_eq!(
            parse_fact_line("attackerLocated(eve, internet, root)."),
            Ok(Some(InputFact::AttackerLocated(
                AttackerStartingPosition::new("eve", "internet", PrivilegeLevel::Root)
            )))
        );
        assert_eq!(
            parse_fact_line("attackGoal(eve, admin01)."),
            Ok(Some(InputFact::AttackGoal(AttackerTargetGoal::new(
                "eve", "admin01"
            ))))
        );
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        assert_eq!(parse_fact_line(""), Ok(None));
        assert_eq!(parse_fact_line("   "), Ok(None));
        assert_eq!(parse_fact_line("% comment"), Ok(None));
        assert_eq!(parse_fact_line("  # another comment"), Ok(None));
    }

    #[test]
    fn rejects_invalid_predicate_names() {
        assert_eq!(
            parse_fact_line("unknownFact(a, b)."),
            Err(ParseError::UnknownPredicate("unknownFact".to_string()))
        );
    }

    #[test]
    fn rejects_invalid_privilege_values() {
        assert_eq!(
            parse_fact_line("attackerLocated(eve, internet, admin)."),
            Err(ParseError::InvalidPrivilege("admin".to_string()))
        );
    }

    #[test]
    fn rejects_missing_period() {
        assert_eq!(
            parse_fact_line("hacl(internet, web01, https)"),
            Err(ParseError::MissingPeriod)
        );
    }

    #[test]
    fn parses_fact_file_into_input_scenario() {
        let path = std::env::temp_dir().join(format!(
            "dynamic_attack_graphs_parser_test_{}.facts",
            std::process::id()
        ));

        std::fs::write(
            &path,
            r#"
                # Enterprise scenario
                vulExists(web01, cve_2024_1234, http, user).
                localVulExists(web01, cve_2024_local, root).
                hacl(internet, web01, http).
                firewallDeny(internet, db01, postgres).
                attackerLocated(eve, internet, user).
                attackGoal(eve, web01).
            "#,
        )
        .expect("test fact file should be writable");

        let scenario = parse_facts_file(&path).expect("test fact file should parse");
        std::fs::remove_file(&path).expect("test fact file should be removable");

        assert_eq!(scenario.vulnerabilities.len(), 1);
        assert_eq!(scenario.local_vulnerabilities.len(), 1);
        assert_eq!(scenario.network_access.len(), 1);
        assert_eq!(scenario.firewall_rules.len(), 1);
        assert_eq!(scenario.attacker_positions.len(), 1);
        assert_eq!(scenario.attacker_goals.len(), 1);
    }

    #[test]
    fn parses_remove_update_lines() {
        assert_eq!(
            parse_update_line("remove(vulExists(web01, cve_2024_1234, http, user))."),
            Ok(Some(InputUpdate::Remove(InputFact::VulExists(
                VulnerabilityRecord::new("web01", "cve_2024_1234", "http", PrivilegeLevel::User)
            ))))
        );
        assert_eq!(
            parse_update_line("remove(hacl(internet, web01, https))."),
            Ok(Some(InputUpdate::Remove(InputFact::Hacl(
                NetworkAccessRule::new("internet", "web01", "https")
            ))))
        );
        assert_eq!(
            parse_update_line("firewallDeny(internet, web01, https)."),
            Ok(Some(InputUpdate::Insert(InputFact::FirewallDeny(
                FirewallRuleRecord::create_deny_rule("internet", "web01", "https")
            ))))
        );
    }
}
