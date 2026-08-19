//! The `loopsvault` command line.
//!
//! Two kinds of command, split by which side of the boundary they sit on:
//!
//! - **Read commands** (`ls`, `describe`, `usage`) ask the running daemon over
//!   loopback. They need no privilege because they return no value.
//! - **Admin commands** (`init`, `set`, `rm`, `export`, `project`) open the
//!   store directly, because they change it.
//!
//! ## Why admin commands open the store directly in v1, and what changes later
//!
//! The handoff's architecture has the CLI talking to the daemon over a Unix
//! domain socket, with the store owned by a `_vaultd` service account so the
//! refusal to read it comes from the kernel. That is right, and it is not what
//! v1 does, because the service account and the launchd plist are part of the
//! macOS system setup that has not landed yet.
//!
//! In v1 the daemon and the CLI both run as the founder, so a direct open grants
//! the CLI nothing the daemon does not already have. When the service account
//! lands, these commands move to the socket and this file's admin paths become
//! thin clients. Recorded in `founder/task-service-account.md` so it is a
//! planned migration rather than a forgotten shortcut.
//!
//! ## Write-only
//!
//! There is no `loopsvault get`. Once a value is stored, this tool will not show
//! it to you. That is a UI policy rather than a cryptographic guarantee, and the
//! handoff is explicit about the difference: a machine that can decrypt in order
//! to use can decrypt in order to display, and on your own Mac you always have
//! root. Its value is behavioural and it is substantial, because peeking at a
//! key and pasting it into a terminal or an agent prompt is where keys actually
//! leak in practice. `export` exists for the case where you genuinely need the
//! values back, and it is deliberately more friction than a `get` would be.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use loopsvault_core::secret::SecretValue;
use loopsvault_core::unwrap::FileUnwrapper;
use loopsvault_core::ProjectId;
use loopsvaultd::config::Config;
use loopsvaultd::store::CredentialStore;

#[derive(Parser)]
#[command(name = "loopsvault", version, about = "Use API keys without seeing them")]
struct Cli {
    #[arg(long, default_value = "~/.loopsvault/config.json", global = true)]
    config: String,

    /// Where the running daemon listens.
    #[arg(long, default_value = "http://127.0.0.1:14322", global = true)]
    daemon: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a config, a master key, and an empty store.
    Init,
    /// Generate catalog entries from an inventory of your projects.
    ///
    /// Only ever ADDS. It will not touch an entry you already have, will not
    /// touch project tokens, and cannot touch values, because an inventory
    /// carries variable names and never contents.
    Bootstrap {
        /// TSV from `tools/inventory/collect.sh`.
        #[arg(long, default_value = "catalog/inventory.tsv")]
        inventory: PathBuf,
        /// Only these providers, comma separated. Default is all recognised.
        #[arg(long)]
        only: Option<String>,
        /// Show what would change and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// List the catalog. Names, purposes and shapes; never values.
    Ls,
    /// Describe one entry, by canonical name or alias.
    Describe { name: String },
    /// Store a value. Read from stdin, never from an argument.
    Set {
        name: String,
        /// Store under a name the catalog does not know. Almost always a typo,
        /// so it has to be asked for.
        #[arg(long)]
        force: bool,
    },
    /// Delete a value.
    Rm {
        #[arg(default_value = "")]
        name: String,
        /// Delete every stored value no catalog entry answers to, without
        /// having to name it. Naming it is the thing to avoid when the name is
        /// itself a credential.
        #[arg(long)]
        orphans: bool,
    },
    /// Per-project usage and cost.
    Usage,
    /// Write an encrypted break-glass export.
    Export { out: PathBuf },
    /// Per-project tokens.
    #[command(subcommand)]
    Project(ProjectCmd),
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Register a project and print its token, once.
    Add { name: String },
    /// List registered projects.
    Ls,
    /// Revoke a project's token.
    Rm { name: String },
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);

    match cli.command {
        Command::Init => init(&config_path),
        Command::Bootstrap {
            inventory,
            only,
            dry_run,
        } => bootstrap(&config_path, &inventory, only.as_deref(), dry_run),
        Command::Ls => remote_get(&cli.daemon, "/catalog", render_catalog),
        Command::Describe { name } => {
            remote_get(&cli.daemon, &format!("/catalog/{name}"), render_entry)
        }
        Command::Usage => remote_get(&cli.daemon, "/usage", render_usage),
        Command::Set { name, force } => set(&config_path, &name, force),
        Command::Rm { name, orphans } => rm(&config_path, &name, orphans),
        Command::Export { out } => export(&config_path, &out),
        Command::Project(cmd) => project(&config_path, cmd),
    }
}

fn open_store(config_path: &PathBuf) -> anyhow::Result<(Config, CredentialStore)> {
    let cfg = Config::load(config_path).with_context(|| {
        format!(
            "loading {}. Run `loopsvault init` if this is a new machine.",
            config_path.display()
        )
    })?;
    let unwrapper = FileUnwrapper::new(&cfg.master_key_path);
    let store = CredentialStore::open(&cfg.store_path, &unwrapper)?;
    Ok((cfg, store))
}

fn init(config_path: &PathBuf) -> anyhow::Result<()> {
    if config_path.exists() {
        bail!(
            "{} already exists. Refusing to overwrite it: that would orphan every value \
             in the existing store.",
            config_path.display()
        );
    }
    let dir = config_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;

    let key_path = dir.join("master.key");
    let store_path = dir.join("vault.store");

    // 32 bytes of system randomness, hex encoded.
    let mut bytes = [0u8; 32];
    getrandom_bytes(&mut bytes)?;
    let mut key = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(key, "{b:02x}");
    }
    write_private(&key_path, key.as_bytes())?;

    let cfg = serde_json::json!({
        "store_path": store_path,
        "master_key_path": key_path,
        "catalog": {"entries": []},
        "projects": {"records": []},
        "providers": {},
        "prices": {}
    });
    std::fs::write(config_path, serde_json::to_vec_pretty(&cfg)?)?;

    println!("Created {}", config_path.display());
    println!("Created {} (mode 0600)", key_path.display());
    println!();
    println!("The master key is the only thing that can decrypt your store.");
    println!("Run `loopsvault export <path>` once you have values in it, and keep");
    println!("that export somewhere other than this machine. Without it, a lost");
    println!("master key means rotating every credential across every project.");
    Ok(())
}

/// Turn an inventory of every project into catalog entries.
///
/// The founder has 100 real secrets across 28 projects. Writing a catalog entry
/// for each by hand is the friction that kills adoption before the daemon ever
/// brokers a real call, so the provider knowledge lives in a table
/// (`loopsvault_core::providers`) and the entries are generated from it.
///
/// Safety properties, because this writes to the file that governs credential
/// routing:
///
/// - It only ADDS. An entry that already exists is left exactly as it is and
///   reported as skipped, so a hand-tuned host list is never silently widened.
/// - It never touches `projects` (the token registry), `store_path` or
///   `master_key_path`.
/// - It cannot leak a value, because an inventory holds names, lengths and
///   character classes and never contents.
fn bootstrap(
    config_path: &PathBuf,
    inventory: &PathBuf,
    only: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    use loopsvault_core::catalog::{CatalogEntry, Classification};
    use loopsvault_core::providers::{profile_for, Confidence};
    use std::collections::{BTreeMap, BTreeSet};

    let mut cfg = Config::load(config_path).with_context(|| {
        format!(
            "loading {}. Run `loopsvault init` first.",
            config_path.display()
        )
    })?;

    let raw = std::fs::read_to_string(inventory).with_context(|| {
        format!(
            "reading {}. Generate it with:\n  bash tools/inventory/collect.sh > {}",
            inventory.display(),
            inventory.display()
        )
    })?;

    let wanted: Option<BTreeSet<&str>> = only.map(|s| s.split(',').map(|x| x.trim()).collect());

    // canonical provider key -> projects that use it, under any of its names.
    let mut usage: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let mut unrecognised: BTreeSet<String> = BTreeSet::new();

    for line in raw.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 {
            continue;
        }
        let (project, name, kind) = (f[0], f[2], f[5]);
        // Example and template files document intended names but describe no
        // real deployment, so they must not create a permission.
        if kind != "real" {
            continue;
        }
        match profile_for(name) {
            Some(p) => {
                if let Some(w) = &wanted {
                    if !w.contains(p.key) {
                        continue;
                    }
                }
                usage.entry(p.key).or_default().insert(project.to_string());
            }
            None => {
                unrecognised.insert(name.to_string());
            }
        }
    }

    if usage.is_empty() {
        println!("Nothing recognised in {}.", inventory.display());
        println!("Known providers: {}", loopsvault_core::PROFILES.iter().map(|p| p.key).collect::<Vec<_>>().join(", "));
        return Ok(());
    }

    let mut added = Vec::new();
    let mut skipped = Vec::new();
    let mut needs_confirming = Vec::new();

    for (key, projects) in &usage {
        let p = loopsvault_core::providers::profile_by_key(key).expect("key came from the table");
        let canonical = p.canonical_name();

        if cfg.catalog.get(canonical).is_ok() {
            skipped.push(format!("{canonical} (already in your catalog)"));
            continue;
        }

        let confirm = p.confidence == Confidence::Likely;
        let mut comment = format!(
            "{}. Used by {} project{}: {}.",
            p.note.trim_end_matches('.'),
            projects.len(),
            if projects.len() == 1 { "" } else { "s" },
            projects.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        if confirm {
            // Carried in the comment, not just printed once, so it is still
            // visible in `loopsvault describe` months from now.
            comment.insert_str(
                0,
                "CONFIRM THE PLACEMENT BEFORE RELYING ON THIS. ",
            );
            needs_confirming.push(canonical.to_string());
        }

        cfg.catalog.entries.push(CatalogEntry {
            name: canonical.to_string(),
            aliases: p.aliases().iter().map(|s| s.to_string()).collect(),
            provider: p.key.to_string(),
            comment,
            expiry: None,
            projects: projects.iter().cloned().collect(),
            shape: None,
            classification: Classification::Secret,
            hosts: p.hosts.iter().map(|s| s.to_string()).collect(),
            placement: Some(p.placement()),
            honeytoken: false,
        });

        cfg.providers.entry(p.key.to_string()).or_insert_with(|| {
            loopsvaultd::config::ProviderConfig {
                upstream: p.upstream.to_string(),
                credential: canonical.to_string(),
            }
        });

        added.push(format!(
            "{canonical:<24} {} project{:<2} -> {}",
            projects.len(),
            if projects.len() == 1 { "" } else { "s" },
            p.hosts.join(", ")
        ));
    }

    // Validate before writing. A generated config that stops the daemon booting
    // would be a worse outcome than not generating one.
    cfg.validate().context("the generated config failed validation, nothing was written")?;

    println!("Added {} entr{}:", added.len(), if added.len() == 1 { "y" } else { "ies" });
    for a in &added {
        println!("  {a}");
    }
    if !skipped.is_empty() {
        println!("\nLeft alone:");
        for s in &skipped {
            println!("  {s}");
        }
    }
    if !needs_confirming.is_empty() {
        println!("\nConfirm these before relying on them:");
        for n in &needs_confirming {
            println!("  {n}  (its auth header shape is believed correct, not verified)");
        }
        println!("A wrong header earns a 401 from the provider, so this is confusing rather");
        println!("than dangerous. The exact-host rule still holds either way.");
    }
    if !unrecognised.is_empty() {
        println!(
            "\n{} variable names had no provider profile and were left out.",
            unrecognised.len()
        );
        println!("Most are decided constants rather than credentials. Add a profile in");
        println!("crates/loopsvault-core/src/providers.rs for any that should be brokered.");
    }

    if dry_run {
        println!("\nDry run. Nothing was written.");
        return Ok(());
    }

    save_config(config_path, &cfg)?;
    println!("\nWrote {}.", config_path.display());
    println!("No values were read or written; an inventory carries names, not contents.");
    println!("Next: `loopsvault set <NAME>` for each, then start the daemon.");
    Ok(())
}

fn getrandom_bytes(buf: &mut [u8]) -> anyhow::Result<()> {
    // Reuse the same source the daemon uses for project tokens.
    let token = loopsvault_core::ProjectToken::generate()
        .map_err(|e| anyhow::anyhow!("could not read system randomness: {e}"))?;
    let hex = token.expose().trim_start_matches("lvp_");
    for (i, chunk) in hex.as_bytes().chunks(2).take(buf.len()).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap_or(0) as u8;
        buf[i] = (hi << 4) | lo;
    }
    Ok(())
}

/// Read a secret without ever putting it in argv.
///
/// Anything in argv is visible to every process on the machine through `ps`,
/// and it lands in shell history. Two places a credential must never be.
///
/// Interactively this prompts without echo. Non-interactively it reads a line
/// from stdin, so the same command works in a script and in a backup job. That
/// second path is not a convenience: `rpassword` opens the TTY directly, so
/// without it every non-interactive use dies with "Device not configured",
/// which says nothing about what went wrong.
fn read_secret(prompt: &str, take_all: bool) -> anyhow::Result<String> {
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).context("reading from the terminal");
    }
    let mut buf = String::new();
    if take_all {
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("reading from stdin")?;
    } else {
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
            .context("reading from stdin")?;
    }
    Ok(buf)
}

fn set(config_path: &PathBuf, name: &str, force: bool) -> anyhow::Result<()> {
    let (cfg, mut store) = open_store(config_path)?;

    // A value stored under a name no catalog entry answers to is invisible
    // forever: nothing looks it up, and `ls` goes on reporting the real
    // credential as missing. `set` used to accept any string and report
    // success, so a single typo produced a silent no-op that looked like a
    // working command. Refuse instead, and say what was probably meant.
    // A variable NAME is an identifier. A value is not. Checked BEFORE the
    // catalog lookup and NOT overridable by --force, because the failure this
    // catches is not a typo, it is the key itself arriving in the name
    // position, which happened on 2026-08-19 and put a live credential into a
    // catalog name, an unauthenticated HTTP response and an agent's context.
    //
    // The name comes from argv, and argv is visible to every process through
    // `ps` and lands in shell history. That is exactly why the VALUE is read
    // from stdin, and it is why a value must never be accepted here.
    if !name.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!(
            "{} is not a variable name.\n\n\
             A name is an identifier: letters, digits and underscores, starting with a letter \
             or underscore. What you passed looks like a VALUE.\n\n\
             If you pasted a credential here, it went into argv, which means it is in your \
             shell history and was visible to every process on this machine. TREAT IT AS \
             COMPROMISED AND ROTATE IT.\n\n\
             The value is never passed as an argument. Run `loopsvault set <NAME>` and paste \
             it at the prompt, or pipe it on stdin.",
            if name.len() > 8 { format!("{}...({} chars)", &name[..4], name.len()) } else { name.to_string() }
        );
    }

    if !force && cfg.catalog.get(name).is_err() {
        let known = cfg.catalog.names();
        let near: Vec<&str> = known
            .iter()
            .copied()
            .filter(|k| {
                k.eq_ignore_ascii_case(name)
                    || k.to_ascii_uppercase().contains(&name.to_ascii_uppercase())
                    || name.to_ascii_uppercase().contains(&k.to_ascii_uppercase())
            })
            .collect();

        let mut msg = format!("no catalog entry answers to {name}, so a value stored under it would never be used.\n");
        if !near.is_empty() {
            msg.push_str(&format!("Did you mean: {}\n", near.join(", ")));
        }
        msg.push_str(&format!(
            "Known names: {}\n\nAdd it to the catalog first, or pass --force if you really mean a name nothing references.",
            if known.is_empty() { "(the catalog is empty)".to_string() } else { known.join(", ") }
        ));
        bail!("{msg}");
    }

    let value = read_secret(&format!("Value for {name} (not echoed): "), true)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("refusing to store an empty value for {name}");
    }

    let secret = SecretValue::new(value);
    let shape = secret.shape();
    store.put(name, secret)?;

    // Confirm by shape, never by content. This is enough to catch the two
    // mistakes that actually happen, a truncated paste and the wrong key in the
    // wrong slot, without printing a character of it.
    println!("Stored {name}: {} bytes, {:?}", shape.len, shape.class);
    println!("It cannot be read back. `loopsvault export` is the only way out.");
    Ok(())
}

fn rm(config_path: &PathBuf, name: &str, orphans: bool) -> anyhow::Result<()> {
    let (cfg, mut store) = open_store(config_path)?;

    if orphans {
        let doomed: Vec<String> = store
            .names()
            .into_iter()
            .filter(|n| cfg.catalog.get(n).is_err())
            .map(String::from)
            .collect();
        if doomed.is_empty() {
            println!("No unclaimed values. Nothing to do.");
            return Ok(());
        }
        for d in &doomed {
            store.remove(d)?;
            let shown = if d.len() > 8 { format!("{}...({} chars)", &d[..4], d.len()) } else { d.clone() };
            println!("Deleted {shown}.");
        }
        println!("\nIf any of those were a credential pasted into the name position, it \
                  reached argv and your shell history. Rotate it.");
        return Ok(());
    }

    if name.is_empty() {
        bail!("give a name, or --orphans to clear everything unclaimed");
    }
    if store.remove(name)? {
        println!("Deleted {name}.");
    } else {
        println!("{name} had no stored value. Nothing to do.");
    }
    Ok(())
}

fn export(config_path: &PathBuf, out: &PathBuf) -> anyhow::Result<()> {
    let (_cfg, store) = open_store(config_path)?;

    let interactive = std::io::stdin().is_terminal();
    let pass = read_secret("Passphrase for the export: ", false)?
        .trim_end_matches('\n')
        .to_string();

    // Only ask twice when a human is typing. In a script there is nothing to
    // mistype, and demanding a second copy just makes the command unusable in
    // the backup job this export exists for.
    if interactive {
        let again = read_secret("Again: ", false)?.trim_end_matches('\n').to_string();
        if pass != again {
            bail!("passphrases did not match");
        }
    }
    if pass.len() < 12 {
        bail!("use a passphrase of at least 12 characters; this file holds everything");
    }

    let bytes = store.export_break_glass(&SecretValue::new(pass))?;
    write_private(out, &bytes)?;
    println!("Wrote {} (mode 0600).", out.display());
    println!();
    println!("This is a plain age file. `age -d` can recover it with no LoopsVault");
    println!("build, which matters because the moment you need it is the moment");
    println!("something else has stopped working. Keep it off this machine.");
    Ok(())
}

fn project(config_path: &PathBuf, cmd: ProjectCmd) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?;
    match cmd {
        ProjectCmd::Add { name } => {
            let id = ProjectId::parse(&name).map_err(|e| anyhow::anyhow!("{e}"))?;
            let token = cfg
                .projects
                .issue(id)
                .map_err(|e| anyhow::anyhow!("issuing a token: {e}"))?;
            save_config(config_path, &cfg)?;
            println!("{}", token.expose());
            eprintln!();
            eprintln!("Shown once. The daemon stores only a hash of it, so it cannot be");
            eprintln!("printed again. Put it in {name}'s environment as");
            eprintln!("LOOPSVAULT_PROJECT_TOKEN and send it in the");
            eprintln!("x-loopsvault-project-token header.");
            eprintln!();
            eprintln!("If you lose it, run this again; the old one stops working.");
        }
        ProjectCmd::Ls => {
            for p in cfg.projects.projects() {
                println!("{p}");
            }
        }
        ProjectCmd::Rm { name } => {
            let id = ProjectId::parse(&name).map_err(|e| anyhow::anyhow!("{e}"))?;
            if cfg.projects.revoke(&id) {
                save_config(config_path, &cfg)?;
                println!("Revoked {name}. Its token stops working immediately.");
            } else {
                println!("{name} was not registered.");
            }
        }
    }
    Ok(())
}

fn save_config(path: &PathBuf, cfg: &Config) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(cfg)?;
    let tmp = path.with_extension("tmp");
    write_private(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

fn remote_get(
    daemon: &str,
    path: &str,
    render: fn(&serde_json::Value) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let url = format!("{}{}", daemon.trim_end_matches('/'), path);
    let resp = reqwest::blocking::get(&url).with_context(|| {
        format!("asking the daemon at {daemon}. Is loopsvaultd running?")
    })?;

    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().unwrap_or(serde_json::json!({}));
        if let Some(err) = body.get("error").and_then(|e| e.as_str()) {
            eprintln!("{err}");
        }
        if let Some(next) = body.get("next_step").and_then(|e| e.as_str()) {
            eprintln!("{next}");
        }
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().context("parsing the daemon response")?;
    render(&body)
}

fn render_catalog(v: &serde_json::Value) -> anyhow::Result<()> {
    let empty = vec![];
    let entries = v["entries"].as_array().unwrap_or(&empty);
    if entries.is_empty() {
        println!("The catalog is empty.");
        println!("Add entries to the `catalog` section of your config, then");
        println!("`loopsvault set <NAME>` to store each value.");
        return Ok(());
    }
    println!("{:<28} {:<12} {:<7} {}", "NAME", "CLASS", "STORED", "PURPOSE");
    for e in entries {
        println!(
            "{:<28} {:<12} {:<7} {}",
            e["name"].as_str().unwrap_or(""),
            e["classification"].as_str().unwrap_or(""),
            if e["stored"].as_bool().unwrap_or(false) { "yes" } else { "NO" },
            e["comment"].as_str().unwrap_or("")
        );
    }
    if let Some(orphans) = v["orphaned"].as_array().filter(|a| !a.is_empty()) {
        println!();
        println!("STORED BUT UNCLAIMED, nothing will ever use these:");
        for o in orphans {
            // Redacted. An orphan is by definition a name nothing expected, and
            // the way this goes wrong is a credential landing in the name
            // position, so printing them in full turns a diagnostic into a leak.
            let n = o.as_str().unwrap_or("");
            if n.len() > 8 {
                println!("  {}...({} chars)", &n[..4], n.len());
            } else {
                println!("  {n}");
            }
        }
        println!("Each is a value stored under a name no catalog entry answers to,");
        println!("almost always a typo. Add a catalog entry with that name, or");
        println!("`loopsvault rm <name>` and store it again under the right one.");
    }
    println!();
    println!("Values are never shown. To use one, send your request through the daemon.");
    Ok(())
}

fn render_entry(e: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", e["name"].as_str().unwrap_or(""));
    if let Some(a) = e["aliases"].as_array().filter(|a| !a.is_empty()) {
        let names: Vec<&str> = a.iter().filter_map(|x| x.as_str()).collect();
        println!("  also known as  {}", names.join(", "));
    }
    println!("  provider       {}", e["provider"].as_str().unwrap_or(""));
    println!("  purpose        {}", e["comment"].as_str().unwrap_or(""));
    println!("  classification {}", e["classification"].as_str().unwrap_or(""));
    if let Some(hosts) = e["hosts"].as_array() {
        let hs: Vec<&str> = hosts.iter().filter_map(|x| x.as_str()).collect();
        println!("  may be sent to {}", hs.join(", "));
    }
    if let Some(projects) = e["projects"].as_array() {
        let ps: Vec<&str> = projects.iter().filter_map(|x| x.as_str()).collect();
        println!("  usable by      {}", ps.join(", "));
    }
    match (&e["shape"]["len"], &e["shape"]["class"]) {
        (serde_json::Value::Number(n), serde_json::Value::String(c)) => {
            println!("  value shape    {n} bytes, {c}");
        }
        _ => println!("  value shape    no value stored yet"),
    }
    println!();
    println!("The value itself is not available from any command.");
    Ok(())
}

fn render_usage(v: &serde_json::Value) -> anyhow::Result<()> {
    let Some(projects) = v["projects"].as_object() else {
        println!("No usage recorded yet.");
        return Ok(());
    };
    if projects.is_empty() {
        println!("No usage recorded yet.");
        return Ok(());
    }
    println!(
        "{:<24} {:>7} {:>10} {:>10} {:>10}",
        "PROJECT", "CALLS", "IN", "OUT", "USD"
    );
    for (name, u) in projects {
        let micro = u["micro_usd"].as_u64().unwrap_or(0);
        println!(
            "{:<24} {:>7} {:>10} {:>10} {:>10.4}",
            name,
            u["calls"].as_u64().unwrap_or(0),
            u["input_tokens"].as_u64().unwrap_or(0),
            u["output_tokens"].as_u64().unwrap_or(0),
            micro as f64 / 1_000_000.0
        );
        let samples = u["overhead_samples"].as_u64().unwrap_or(0);
        if samples > 0 {
            println!(
                "{:<24} vault overhead: {}ms mean, {}ms worst, over {} calls (provider latency excluded)",
                "",
                u["overhead_ms_total"].as_u64().unwrap_or(0) / samples,
                u["overhead_ms_max"].as_u64().unwrap_or(0),
                samples
            );
        }
        let unpriced = u["unpriced_calls"].as_u64().unwrap_or(0);
        let unmetered = u["unmetered_calls"].as_u64().unwrap_or(0);
        if unpriced > 0 || unmetered > 0 {
            println!(
                "{:<24} {} calls have no dollar figure ({} unpriced model, {} provider reports no tokens)",
                "", unpriced + unmetered, unpriced, unmetered
            );
        }
    }
    println!();
    println!("Exact where the provider reports tokens. fal.ai and Replicate bill on");
    println!("compute time and report none, so those show as calls without dollars");
    println!("rather than as zero.");
    Ok(())
}
