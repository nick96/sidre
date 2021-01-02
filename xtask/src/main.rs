use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use xshell::{cmd, pushd, pushenv};

enum Mode {
    Overwrite,
    // Verify,
}

enum Command {
    PreCommit,
    InstallPreCommit,
    DockerCompose,
}

impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pre-commit" => Ok(Command::PreCommit),
            "install-pre-commit" => Ok(Command::InstallPreCommit),
            "docker-compose" => Ok(Command::DockerCompose),
            "dc" => Ok(Command::DockerCompose),
            _ => bail!("Unknown subcommand: {}", s),
        }
    }
}

enum DockerComposeCommand {
    CheckFmt,
    Lint,
    Test,
}

impl FromStr for DockerComposeCommand {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "check-fmt" => Ok(DockerComposeCommand::CheckFmt),
            "lint" => Ok(DockerComposeCommand::Lint),
            "test" => Ok(DockerComposeCommand::Test),
            _ => bail!("Unknown subcommand: {}", s),
        }
    }
}

fn main() -> Result<()> {
    if std::env::args().next().map(|it| it.contains("pre-commit")) == Some(true)
    {
        run_precommit().context("failed to run pre-commit hook")?;
        return Ok(());
    }

    let args_list: Vec<String> = std::env::args().into_iter().collect();
    ensure!(
        std::env::args().len() >= 2,
        "expected at least 2 args, found {}: {:?}",
        std::env::args().len(),
        args_list,
    );
    let subcommand = Command::from_str(&std::env::args().nth(1).unwrap())?;
    match subcommand {
        Command::PreCommit => {
            run_precommit().context("failed to run pre-commit hook")?
        },
        Command::InstallPreCommit => run_install_precommit()
            .context("failed to install pre-commit hook")?,
        Command::DockerCompose => {
            ensure!(std::env::args().len() == 3);
            let dc_cmd = DockerComposeCommand::from_str(
                &std::env::args().nth(2).unwrap(),
            )?;
            match dc_cmd {
                DockerComposeCommand::CheckFmt => xshell::cmd!(
                    "docker-compose run --remove-orphans --rm sidre-test \
                     cargo +nightly fmt -- --check"
                )
                .run()?,
                DockerComposeCommand::Lint => xshell::cmd!(
                    "docker-compose run --remove-orphans --rm sidre-test \
                     cargo clippy -- -D warnings"
                )
                .run()?,
                DockerComposeCommand::Test => xshell::cmd!(
                    "docker-compose run --remove-orphans --rm sidre-test \
                     cargo test --verbose"
                )
                .run()?,
            }
        },
    }
    Ok(())
}

fn run_precommit() -> Result<()> {
    run_rustfmt(Mode::Overwrite)?;

    let diff =
        cmd!("git diff --diff-filter=MAR --name-only --cached").read()?;

    let root = project_root();
    for line in diff.lines() {
        let file = root.join(line);
        cmd!("git update-index --add {file}").run()?;
    }

    Ok(())
}

fn run_install_precommit() -> Result<()> {
    let hook_path: PathBuf =
        format!("./.git/hooks/pre-commit{}", std::env::consts::EXE_SUFFIX)
            .into();
    let me = std::env::current_exe()?;
    fs::copy(me, hook_path)?;
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}

fn run_rustfmt(mode: Mode) -> Result<()> {
    let _dir = pushd(project_root())?;
    // Some of the directives in rustfmt.toml are nightly only.
    let _e = pushenv("RUSTUP_TOOLCHAIN", "nightly");
    ensure_rustfmt()?;
    let check: &[&str] = match mode {
        Mode::Overwrite => &[][..],
        // Mode::Verify => &["--", "--check"],
    };
    cmd!("cargo fmt {check...}").run()?;
    Ok(())
}

fn ensure_rustfmt() -> Result<()> {
    let out = cmd!("cargo fmt -- --version").read()?;
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN")?;
    if !out.contains(&toolchain) {
        bail!(
            "Failed to run rustfmt from toolchain '{}'. Please run `rustup \
             component add rustfmt --toolchain {}` to install it.",
            toolchain,
            toolchain,
        )
    }
    Ok(())
}
