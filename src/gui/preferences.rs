use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub(super) fn path(name: &str) -> Option<PathBuf> {
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    base.is_absolute().then(|| base.join("VespDex").join(name))
}

pub(super) fn read(path: &Path) -> Option<String> {
    let mut value = String::new();
    File::open(path)
        .ok()?
        .take(64)
        .read_to_string(&mut value)
        .ok()?;
    (value.len() < 64).then_some(value)
}

pub(super) fn write(path: &Path, value: &str) -> Result<()> {
    let folder = path.parent().context("preference has no directory")?;
    fs::create_dir_all(folder)?;
    let mut file = tempfile::NamedTempFile::new_in(folder)?;
    writeln!(file, "{value}")?;
    file.persist(path)?;
    Ok(())
}
