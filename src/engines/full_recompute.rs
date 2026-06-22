use crate::engine::{evaluate_base_facts, AttackGraphEngine, BaseFacts, DerivedFacts, FactUpdate};

#[derive(Debug, Clone, Default)]
pub struct FullRecomputeEngine {
    facts: BaseFacts,
}

impl FullRecomputeEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn facts(&self) -> &BaseFacts {
        &self.facts
    }
}

impl AttackGraphEngine for FullRecomputeEngine {
    fn name(&self) -> &'static str {
        "full-recompute"
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
