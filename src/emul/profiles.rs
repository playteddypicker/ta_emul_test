// not using for now, but we can extend vendors using this module

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub stack_top: u64,
    pub stack_size: u64,
    pub entry_override: Option<u64>,
}

pub fn load_profile(path: &str) -> Result<Profile> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read profile {}", path))?;
    Ok(serde_yaml::from_str(&s)?)
}
