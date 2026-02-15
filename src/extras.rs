//! Extra CLI functionality for man pages and shell completions.

use std::{io, path::Path};

use anyhow::Result;
use clap::{CommandFactory as _, ValueEnum as _};
use clap_complete::Shell;

use crate::cl;

/// Generate man pages to the specified directory.
pub(crate) fn generate_man_pages(dir: &Path) -> Result<()> {
    let cmd = cl::Args::command().name(env!("CARGO_BIN_NAME"));
    clap_mangen::generate_to(cmd, dir)?;
    Ok(())
}

/// Generate shell completions
///
/// If `shell` is specified, generates only for that shell.
/// If `dir` is specified, generates all completions into that directory.
pub(crate) fn generate_shell_completions(shell: Option<Shell>, dir: Option<&Path>) -> Result<()> {
    let name = env!("CARGO_BIN_NAME");
    let mut cmd = cl::Args::command().name(name);

    if let Some(shell) = shell {
        if let Some(dir) = dir {
            clap_complete::generate_to(shell, &mut cmd, name, dir)?;
        } else {
            clap_complete::generate(shell, &mut cmd, name, &mut io::stdout());
        }
    } else if let Some(dir) = dir {
        let shells = Shell::value_variants();
        for shell_i in shells {
            clap_complete::generate_to(*shell_i, &mut cmd, name, dir)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn man_pages_generated() {
        let dir = tempfile::tempdir().unwrap();
        generate_man_pages(dir.path()).unwrap();
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert!(!entries.is_empty());
        for entry in entries {
            let path = entry.unwrap().path();
            assert!(path.extension().is_some_and(|e| e == "1"));
            let content = fs::read_to_string(&path).unwrap();
            assert!(!content.is_empty());
        }
    }

    #[test]
    fn shell_completions_generated() {
        let dir = tempfile::tempdir().unwrap();
        generate_shell_completions(None, Some(dir.path())).unwrap();
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert!(!entries.is_empty());
        for entry in entries {
            let content = fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(!content.is_empty());
        }
    }
}
