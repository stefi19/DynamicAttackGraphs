// Provenance explanation demo.
//
// Run with:
//   cargo run --release --example explain_goal
// Then render with:
//   dot -Tpng explanation_goal.dot -o explanation_goal.png

use std::path::Path;

use dynamic_attack_graphs::{
    evaluate_attack_graph_naive, export_explanation_to_dot, AttackerStartingPosition,
    AttackerTargetGoal, Explainer, Fact, NetworkAccessRule, PrivilegeLevel, ProvenanceBaseFacts,
    ProvenanceDerivedFacts, VulnerabilityRecord,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=================================================");
    println!("  Goal Explanation Export with Graphviz DOT");
    println!("=================================================\n");

    let vulnerabilities = vec![
        VulnerabilityRecord::new("db01", "CVE-2024-DB", "postgres", PrivilegeLevel::Root),
        VulnerabilityRecord::new("admin01", "CVE-2024-8888", "smb", PrivilegeLevel::Root),
    ];
    let network_access = vec![
        NetworkAccessRule::new("internet", "db01", "postgres"),
        NetworkAccessRule::new("db01", "admin01", "smb"),
    ];
    let firewall_rules = Vec::new();
    let attacker_positions = vec![AttackerStartingPosition::new(
        "eve",
        "internet",
        PrivilegeLevel::User,
    )];
    let attacker_goals = vec![AttackerTargetGoal::new("eve", "admin01")];

    let graph = evaluate_attack_graph_naive(
        vulnerabilities.clone(),
        network_access.clone(),
        firewall_rules.clone(),
        attacker_positions.clone(),
        attacker_goals.clone(),
    );

    let explainer = Explainer::new(
        ProvenanceBaseFacts {
            vulnerabilities,
            local_vulnerabilities: Vec::new(),
            network_access,
            firewall_rules,
            attacker_positions,
            attacker_goals,
        },
        ProvenanceDerivedFacts {
            effective_network_access: graph.effective_network_access.into_iter().collect(),
            code_executions: graph.code_executions.into_iter().collect(),
            machines_owned: graph.machines_owned.into_iter().collect(),
            goals_reached: graph.goals_reached.into_iter().collect(),
        },
    );

    let target = Fact::GoalReached {
        attacker_id: "eve".to_string(),
        target: "admin01".to_string(),
    };
    let explanation = explainer
        .explain(&target)
        .expect("demo scenario should reach admin01");

    println!("{}", explanation);

    let output_path = Path::new("explanation_goal.dot");
    export_explanation_to_dot(&explanation, output_path)?;
    println!("Exported {}", output_path.display());
    println!("Render with: dot -Tpng explanation_goal.dot -o explanation_goal.png");

    Ok(())
}
