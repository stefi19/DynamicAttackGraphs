use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::schema::{
    AttackerStartingPosition, AttackerTargetGoal, FirewallRuleRecord, NetworkAccessRule,
    PrivilegeLevel, VulnerabilityRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFact {
    VulExists(VulnerabilityRecord),
    Hacl(NetworkAccessRule),
    FirewallDeny(FirewallRuleRecord),
    AttackerLocated(AttackerStartingPosition),
    AttackGoal(AttackerTargetGoal),
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
