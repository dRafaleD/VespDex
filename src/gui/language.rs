use anyhow::{Context, Result};
use std::path::Path;

use super::preferences;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Language {
    #[default]
    Turkish,
    English,
}

impl Language {
    pub(super) fn text(self, tr: &'static str, en: &'static str) -> &'static str {
        match self {
            Self::Turkish => tr,
            Self::English => en,
        }
    }

    pub(super) fn label(self) -> &'static str {
        self.text("Türkçe", "English")
    }

    pub(super) fn load() -> Self {
        preferences::path("language")
            .map(|path| Self::read(&path))
            .unwrap_or_default()
    }

    fn read(path: &Path) -> Self {
        let value = preferences::read(path);
        match value.as_deref().map(str::trim) {
            Some("en") => Self::English,
            _ => Self::Turkish,
        }
    }

    pub(super) fn save(self) -> Result<()> {
        let path = preferences::path("language").context("LOCALAPPDATA is unavailable")?;
        self.write(&path)
    }

    fn write(self, path: &Path) -> Result<()> {
        preferences::write(path, self.text("tr", "en"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_the_language_and_falls_back_for_invalid_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("VespDex").join("language");
        assert!(Language::read(&path) == Language::Turkish);
        Language::English.write(&path).unwrap();
        assert!(Language::read(&path) == Language::English);
        Language::Turkish.write(&path).unwrap();
        assert!(Language::read(&path) == Language::Turkish);
        preferences::write(&path, "unknown").unwrap();
        assert!(Language::read(&path) == Language::Turkish);
    }
}
