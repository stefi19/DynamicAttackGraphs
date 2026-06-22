use crate::engine::{evaluate_base_facts, AttackGraphEngine, BaseFacts, DerivedFacts, FactUpdate};

#[derive(Debug, Clone, Default)]
pub struct NaiveEngine {
    facts: BaseFacts,
}

impl NaiveEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AttackGraphEngine for NaiveEngine {
    fn name(&self) -> &'static str {
        "naive-fixpoint"
    }

    fn load_snapshot(&mut self, facts: BaseFacts) {
        self.facts = facts;
    }

    fn apply_update(&mut self, update: FactUpdate) {
        self.facts.apply_update(update);
    }

    fn current_derived_facts(&self) -> DerivedFacts {
        evaluate_base_facts(&self.facts)
    }
}
