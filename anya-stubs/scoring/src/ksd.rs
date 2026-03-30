// Anya scoring module.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownSample {
    pub tlsh: String,
    pub sha256: String,
    pub family: String,
    pub function: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KsdMatch {
    pub family: String,
    pub function: String,
    pub distance: u32,
    pub confidence: String,
    pub reference_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

pub struct KnownSampleDb {
    _private: (),
}

pub struct KsdStats {
    pub total_samples: usize,
    pub families: std::collections::HashMap<String, usize>,
}

impl KnownSampleDb {
    pub fn new() -> Self {
        Self { _private: () }
    }
    pub fn load(_user_overlay_path: Option<&Path>) -> Self {
        Self::new()
    }
    pub fn find_nearest(&self, _tlsh_hex: &str, _max_distance: u32) -> Option<KsdMatch> {
        None
    }
    pub fn import_calibration(_path: &Path) -> Result<Vec<KnownSample>, String> {
        Ok(Vec::new())
    }
    pub fn save_overlay(_samples: &[KnownSample], _path: &Path) -> Result<(), String> {
        Ok(())
    }
    pub fn remove_from_overlay(_sha256: &str, _path: &Path) -> Result<(), String> {
        Ok(())
    }
    pub fn stats(&self) -> KsdStats {
        KsdStats {
            total_samples: 0,
            families: std::collections::HashMap::new(),
        }
    }
    pub fn samples(&self) -> &[KnownSample] {
        &[]
    }
    pub fn len(&self) -> usize {
        0
    }
    pub fn is_empty(&self) -> bool {
        true
    }
}

impl Default for KnownSampleDb {
    fn default() -> Self {
        Self::new()
    }
}

pub fn similarity_label(_distance: u32) -> String {
    String::new()
}
