//! funsecret 命令行入口与子命令实现。

use std::ffi::OsString;
use std::io::{self, Read, Write};

use clap::{Args, Parser, Subcommand};
use funsecret_core::{
    clear_secret_db, load_secret_db, save_secret_db, SecretManage, DEFAULT_DB_URL_CATEGORY,
};

#[derive(Parser, Debug)]
#[command(
    name = "funsecret",
    version,
    about = "Local-first encrypted secret manager CLI"
)]
pub struct Cli {
    /// Print more detailed logs.
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Read a secret by category path (2 to 5 segments).
    Read(ReadArgs),
    /// Write a secret by category path (2 to 5 segments).
    Write(WriteArgs),
    /// Delete a single secret by category path (2 to 5 segments).
    #[command(visible_alias = "rm")]
    Delete(DeleteArgs),
    /// List all secret paths without displaying values.
    List(ListArgs),
    /// Show current storage backend and secret count.
    Info(InfoArgs),
    /// Clear all secrets in the current database.
    Clear(ClearArgs),
    /// Load secrets from an external database into the local store.
    Load(SyncArgs),
    /// Save local secrets to an external database.
    Save(SyncArgs),
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    /// Secret category path: CATE1 CATE2 [CATE3] [CATE4] [CATE5].
    #[arg(value_name = "CATEGORY", required = true)]
    pub categories: Vec<String>,

    /// Print output as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct WriteArgs {
    /// Read the secret value from stdin instead of the first positional argument.
    #[arg(long)]
    pub stdin: bool,

    /// Optional expiration time (relative seconds if < 1000000000, else Unix timestamp).
    #[arg(long, value_name = "SECONDS")]
    pub expire: Option<i64>,

    /// Print output as JSON.
    #[arg(long)]
    pub json: bool,

    /// VALUE CATE1 CATE2 [CATE3] [CATE4] [CATE5], or only categories when --stdin is set.
    #[arg(value_name = "ARG", required = true)]
    pub args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Secret category path: CATE1 CATE2 [CATE3] [CATE4] [CATE5].
    #[arg(value_name = "CATEGORY", required = true)]
    pub categories: Vec<String>,

    /// Print output as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Print entries with metadata as JSON (values are never included).
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Print storage metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ClearArgs {
    /// Clear all secrets without interactive confirmation.
    #[arg(long)]
    pub yes: bool,

    /// Print output as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SyncArgs {
    /// Database URL (defaults to stored 'funsecret db url' if omitted).
    #[arg(value_name = "DB_URL")]
    pub db_url: Option<String>,

    /// Cipher key for the remote database.
    #[arg(long = "cipher-key", value_name = "KEY")]
    pub cipher_key: Option<String>,

    /// Print output as JSON.
    #[arg(long)]
    pub json: bool,
}

fn pad_categories(categories: &[String], cmd: &str) -> Result<[String; 5], String> {
    if categories.len() < 2 || categories.len() > 5 {
        return Err(format!("{cmd} requires 2 to 5 category arguments"));
    }
    let mut padded = [
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ];
    for (idx, item) in categories.iter().enumerate() {
        padded[idx] = item.clone();
    }
    Ok(padded)
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "warn" };
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default))
        .format_timestamp_secs()
        .try_init();
}

/// 解析参数并执行，返回进程退出码（0 成功，1 执行失败，2 用法错误）。
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return if error.use_stderr() { 2 } else { 0 };
        }
    };

    init_logging(cli.verbose);

    match cli.command {
        Command::Read(args) => cmd_read(args),
        Command::Write(args) => cmd_write(args),
        Command::Delete(args) => cmd_delete(args),
        Command::List(args) => cmd_list(args),
        Command::Info(args) => cmd_info(args),
        Command::Clear(args) => cmd_clear(args),
        Command::Load(args) => cmd_sync(args, true),
        Command::Save(args) => cmd_sync(args, false),
    }
}

fn cmd_read(args: ReadArgs) -> i32 {
    let padded = match pad_categories(&args.categories, "read") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 2;
        }
    };
    let manage = match SecretManage::new(None, None, None) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };
    match manage.read(
        &padded[0], &padded[1], &padded[2], &padded[3], &padded[4], None, false, true, None,
    ) {
        Ok(Some(value)) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "path": args.categories,
                        "value": value,
                    })
                );
            } else {
                println!("{value}");
            }
            0
        }
        Ok(None) => 1,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn cmd_write(args: WriteArgs) -> i32 {
    let (value, categories) = if args.stdin {
        let mut buf = String::new();
        if let Err(err) = io::stdin().read_to_string(&mut buf) {
            eprintln!("error: failed to read stdin: {err}");
            return 1;
        }
        (buf, args.args.as_slice())
    } else {
        if args.args.len() < 3 || args.args.len() > 6 {
            eprintln!("error: write requires VALUE followed by 2 to 5 category arguments");
            return 2;
        }
        (args.args[0].clone(), &args.args[1..])
    };

    let padded = match pad_categories(categories, "write") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 2;
        }
    };

    let manage = match SecretManage::new(None, None, None) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };

    match manage.write(
        &value,
        &padded[0],
        &padded[1],
        &padded[2],
        &padded[3],
        &padded[4],
        true,
        args.expire,
    ) {
        Ok(()) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "written": true,
                        "path": categories,
                    })
                );
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn cmd_delete(args: DeleteArgs) -> i32 {
    let padded = match pad_categories(&args.categories, "delete") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 2;
        }
    };
    let manage = match SecretManage::new(None, None, None) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };
    match manage.delete(
        &padded[0], &padded[1], &padded[2], &padded[3], &padded[4], true,
    ) {
        Ok(true) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "deleted": true,
                        "path": args.categories,
                    })
                );
            } else {
                println!("deleted");
            }
            0
        }
        Ok(false) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "deleted": false,
                        "path": args.categories,
                    })
                );
            } else {
                eprintln!("error: secret not found");
            }
            1
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn cmd_list(args: ListArgs) -> i32 {
    let manage = match SecretManage::new(None, None, None) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };
    match manage.list_entries(true) {
        Ok(entries) => {
            if args.json {
                match serde_json::to_string(&entries) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("error: {err}");
                        return 1;
                    }
                }
            } else {
                for entry in entries {
                    println!("{}", entry.display_path);
                }
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn cmd_info(args: InfoArgs) -> i32 {
    let manage = match SecretManage::new(None, None, None) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };
    match manage.info() {
        Ok(info) => {
            if args.json {
                match serde_json::to_string(&info) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("error: {err}");
                        return 1;
                    }
                }
            } else {
                println!("backend: {}", info.backend);
                println!("database_url: {}", info.database_url);
                if let Some(file) = info.database_file {
                    println!("database_file: {file}");
                }
                println!("secret_count: {}", info.secret_count);
                println!(
                    "cipher_key_configured: {}",
                    if info.cipher_key_configured {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!("mysql_example_url: {}", info.mysql_example_url);
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn cmd_clear(args: ClearArgs) -> i32 {
    if !args.yes {
        eprint!("This will delete all stored secrets. Continue? [y/N]: ");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            return 1;
        }
        let normalized = answer.trim().to_ascii_lowercase();
        if normalized != "y" && normalized != "yes" {
            return 1;
        }
    }

    match clear_secret_db(None, None) {
        Ok(count) => {
            if args.json {
                println!("{}", serde_json::json!({ "cleared": count }));
            } else {
                println!("cleared");
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn resolve_db_url(db_url: Option<String>) -> Result<String, String> {
    if let Some(url) = db_url {
        if !url.is_empty() {
            return Ok(url);
        }
    }
    let manage = SecretManage::new(None, None, None).map_err(|e| e.to_string())?;
    let stored = manage
        .read(
            DEFAULT_DB_URL_CATEGORY[0],
            DEFAULT_DB_URL_CATEGORY[1],
            DEFAULT_DB_URL_CATEGORY[2],
            "",
            "",
            None,
            false,
            true,
            None,
        )
        .map_err(|e| e.to_string())?;
    match stored {
        Some(url) if !url.is_empty() => Ok(url),
        _ => {
            let category = DEFAULT_DB_URL_CATEGORY.join(" ");
            Err(format!(
                "No database URL given and no default is stored. Pass a URL, or store a default with: funsecret write <url> {category}"
            ))
        }
    }
}

fn cmd_sync(args: SyncArgs, is_load: bool) -> i32 {
    let url = match resolve_db_url(args.db_url) {
        Ok(u) => u,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 2;
        }
    };
    let result = if is_load {
        load_secret_db(Some(&url), args.cipher_key.as_deref())
    } else {
        save_secret_db(Some(&url), args.cipher_key.as_deref())
    };
    match result {
        Ok(count) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": if is_load { "load" } else { "save" },
                        "synced": count,
                    })
                );
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_exits_zero_and_lists_commands() {
        assert_eq!(run(["funsecret", "--help"]), 0);
        let err = Cli::try_parse_from(["funsecret", "--help"]).unwrap_err();
        let text = err.to_string();
        for cmd in [
            "read", "write", "delete", "list", "info", "clear", "load", "save",
        ] {
            assert!(text.contains(cmd), "missing {cmd} in help:\n{text}");
        }
    }

    #[test]
    fn help_text_is_ascii_only() {
        let mut command = <Cli as clap::CommandFactory>::command();
        command.build();
        let mut pending = vec![command];
        while let Some(current) = pending.pop() {
            let rendered = current.clone().render_long_help().to_string();
            assert!(
                rendered.is_ascii(),
                "`{}` help contains non-ASCII text:\n{rendered}",
                current.get_name()
            );
            pending.extend(current.get_subcommands().cloned());
        }
    }

    #[test]
    fn rejects_invalid_category_counts_with_usage_error() {
        assert_eq!(run(["funsecret", "read", "only_one"]), 2);
        assert_eq!(run(["funsecret", "read", "a", "b", "c", "d", "e", "f"]), 2);
        assert_eq!(run(["funsecret", "write", "val", "only_one"]), 2);
        assert_eq!(run(["funsecret", "delete", "only_one"]), 2);
    }

    #[test]
    fn parses_write_with_stdin_and_expire() {
        let cli = Cli::try_parse_from([
            "funsecret",
            "write",
            "--stdin",
            "--expire",
            "3600",
            "--json",
            "openai",
            "prod",
            "api_key",
        ])
        .unwrap();
        let Command::Write(args) = cli.command else {
            panic!("expected write");
        };
        assert!(args.stdin);
        assert_eq!(args.expire, Some(3600));
        assert!(args.json);
        assert_eq!(args.args, vec!["openai", "prod", "api_key"]);
    }
}
