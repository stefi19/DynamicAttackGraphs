use dynamic_attack_graphs::{
    compare_derived_facts, AttackGraphEngine, AttackerStartingPosition, AttackerTargetGoal,
    BaseFacts, DifferentialEngine, FactUpdate, FirewallRuleRecord, FullRecomputeEngine,
    LocalVulnerabilityRecord, NetworkAccessRule, PrivilegeLevel, VulnerabilityRecord,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SERVICES: &[&str] = &["ssh", "http", "https", "postgres", "smb"];

#[test]
fn randomized_correctness() {
    let seed_count = std::env::var("RANDOMIZED_TEST_SEEDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100);

    for seed in 0..seed_count {
        let mut rng = StdRng::seed_from_u64(seed);
        let facts = generate_scenario(&mut rng);
        let updates = generate_updates(&mut rng, &facts);

        assert_engines_match(seed, None, &facts);

        let mut current_facts = facts;
        for (update_index, update) in updates.into_iter().enumerate() {
            current_facts.apply_update(update.clone());
            assert_engines_match(seed, Some((update_index, &update)), &current_facts);
        }
    }
}

fn assert_engines_match(seed: u64, update: Option<(usize, &FactUpdate)>, facts: &BaseFacts) {
    let mut differential = DifferentialEngine::new();
    let mut recompute = FullRecomputeEngine::new();

    differential.load_snapshot(facts.clone());
    recompute.load_snapshot(facts.clone());

    let differential_output = differential.current_derived_facts();
    let recompute_output = recompute.current_derived_facts();

    if let Err(diff) = compare_derived_facts(&differential_output, &recompute_output) {
        match update {
            Some((index, applied_update)) => panic!(
                "randomized correctness failed for seed {seed}, update index {index}, update {applied_update:?}\n{diff}"
            ),
            None => panic!("randomized correctness failed for seed {seed}, initial snapshot\n{diff}"),
        }
    }
}

fn generate_scenario(rng: &mut StdRng) -> BaseFacts {
    let host_count = rng.gen_range(3..=12);
    let hosts: Vec<_> = (0..host_count)
        .map(|index| format!("host_{index}"))
        .collect();

    let mut network_access = Vec::new();
    for source in &hosts {
        for destination in &hosts {
            if source != destination && rng.gen_bool(0.25) {
                network_access.push(NetworkAccessRule::new(
                    source,
                    destination,
                    choose_service(rng),
                ));
            }
        }
    }

    // Ensure every randomized scenario has at least a simple candidate path.
    for window in hosts.windows(2) {
        network_access.push(NetworkAccessRule::new(&window[0], &window[1], "https"));
    }

    let mut vulnerabilities = Vec::new();
    for host in hosts.iter().skip(1) {
        for service in SERVICES {
            if rng.gen_bool(0.28) {
                vulnerabilities.push(VulnerabilityRecord::new(
                    host,
                    &format!("CVE-{host}-{service}"),
                    service,
                    random_privilege(rng),
                ));
            }
        }
    }
    for host in hosts.iter().skip(1) {
        vulnerabilities.push(VulnerabilityRecord::new(
            host,
            &format!("CVE-{host}-path"),
            "https",
            random_privilege(rng),
        ));
    }

    let local_vulnerabilities = hosts
        .iter()
        .filter(|_| rng.gen_bool(0.2))
        .map(|host| {
            LocalVulnerabilityRecord::new(host, &format!("CVE-{host}-local"), PrivilegeLevel::Root)
        })
        .collect();

    let firewall_rules = network_access
        .iter()
        .filter(|_| rng.gen_bool(0.08))
        .map(|access| {
            FirewallRuleRecord::create_deny_rule(
                &access.source_host,
                &access.destination_host,
                &access.service_name,
            )
        })
        .collect();

    BaseFacts {
        vulnerabilities,
        local_vulnerabilities,
        network_access,
        firewall_rules,
        attacker_positions: vec![AttackerStartingPosition::new(
            "eve",
            &hosts[0],
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("eve", hosts.last().unwrap())],
    }
}

fn generate_updates(rng: &mut StdRng, facts: &BaseFacts) -> Vec<FactUpdate> {
    let mut updates = Vec::new();

    if let Some(vulnerability) = facts
        .vulnerabilities
        .get(rng.gen_range(0..facts.vulnerabilities.len()))
    {
        updates.push(FactUpdate::RemoveVulnerability(vulnerability.clone()));
    }

    if let Some(access) = facts
        .network_access
        .get(rng.gen_range(0..facts.network_access.len()))
    {
        updates.push(FactUpdate::InsertFirewallDeny(
            FirewallRuleRecord::create_deny_rule(
                &access.source_host,
                &access.destination_host,
                &access.service_name,
            ),
        ));
    }

    let new_host = format!("host_{}", rng.gen_range(0..12));
    updates.push(FactUpdate::InsertVulnerability(VulnerabilityRecord::new(
        &new_host,
        &format!("CVE-{new_host}-new"),
        choose_service(rng),
        random_privilege(rng),
    )));

    updates.push(FactUpdate::InsertLocalVulnerability(
        LocalVulnerabilityRecord::new(
            &new_host,
            &format!("CVE-{new_host}-new-local"),
            PrivilegeLevel::Root,
        ),
    ));

    updates
}

fn choose_service(rng: &mut StdRng) -> &'static str {
    SERVICES[rng.gen_range(0..SERVICES.len())]
}

fn random_privilege(rng: &mut StdRng) -> PrivilegeLevel {
    if rng.gen_bool(0.55) {
        PrivilegeLevel::User
    } else {
        PrivilegeLevel::Root
    }
}
