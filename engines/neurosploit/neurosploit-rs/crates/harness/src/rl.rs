//! Lightweight reinforcement-learning reward store for the harness.
//!
//! Each agent carries a weight in [0.05, 1.0]; validated findings reward it,
//! idle runs decay it slightly. Weights bias agent ordering on future runs and
//! persist to a JSON file so the harness gets sharper over time.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
pub struct RlState {
    #[serde(default)]
    pub weights: HashMap<String, f64>,
    #[serde(default)]
    pub runs: u64,
}

const ALPHA: f64 = 0.3;
const WMIN: f64 = 0.05;
const WMAX: f64 = 1.0;

impl RlState {
    pub fn load(path: &Path) -> RlState {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn weight(&self, agent: &str) -> f64 {
        *self.weights.get(agent).unwrap_or(&0.5)
    }

    /// Reward in [-1, 1]; e.g. severity-weighted hits positive, idle negative.
    pub fn update(&mut self, agent: &str, reward: f64) {
        let w = self.weights.entry(agent.to_string()).or_insert(0.5);
        *w = (*w + ALPHA * (reward - *w)).clamp(WMIN, WMAX);
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, s);
        }
    }
}

/// Severity → reward weight.
pub fn severity_reward(sev: &str) -> f64 {
    match sev {
        "Critical" => 1.0,
        "High" => 0.7,
        "Medium" => 0.4,
        "Low" => 0.2,
        _ => 0.05,
    }
}
