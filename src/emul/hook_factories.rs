use anyhow::Result;

use crate::emul::hook_strategies::{HookingStrategy, DefaultHookingStrategy, TracingHookingStrategy};

pub enum HookingStrategyType {
    Default,
    Tracing,
}

pub struct HookingStrategyFactory;

impl HookingStrategyFactory {
    pub fn create_strategy(strategy_type: HookingStrategyType) -> Result<Box<dyn HookingStrategy>> {
        match strategy_type {
            HookingStrategyType::Default => Ok(Box::new(DefaultHookingStrategy)),
            HookingStrategyType::Tracing => Ok(Box::new(TracingHookingStrategy)),
        }
    }
}
