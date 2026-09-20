use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use certmatch::logic::{chain_order_valid, keys_match, split_cert_bundle};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "certmatch",
    about = "Verifies a certificate and private key belong together, and that a chain is correctly ordered"
)]
struct Cli {
    #[command(subcommand)]
    command: Command2,
}

#[derive(Subcommand)]
enum Command2 {
    /// Check that a certificate and private key belong together.
    CheckPair { cert: PathBuf, key: PathBuf },
    /// Check that a multi-certificate chain file is correctly ordered.
    CheckChain { chain: PathBuf },
}

/// Runs `openssl <args>`, feeding `stdin` (a PEM blob) to it, and
/// returns stdout as text — used for every real cert/key introspection
/// this tool does, rather than reimplementing X.509/PKCS8 parsing.
fn run_openssl(args: &[&str], stdin: &str) -> anyhow::Result<String> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn cert_pubkey(cert_pem: &str) -> anyhow::Result<String> {
    run_openssl(&["x509", "-noout", "-pubkey"], cert_pem)
}

fn key_pubkey(key_pem: &str) -> anyhow::Result<String> {
    // Deliberately no `-noout` here: on at least one real OpenSSL build
    // this was tested against, `openssl pkey -noout -pubout` silently
    // produces *no* output at all (exit 0, empty stdout, empty stderr) —
    // `-noout` and `-pubout` don't compose the way they do for `x509`.
    // Found live (a genuinely matching cert/key pair was reported as a
    // mismatch because this command produced nothing to compare against).
    run_openssl(&["pkey", "-pubout"], key_pem)
}

fn cert_subject(cert_pem: &str) -> anyhow::Result<String> {
    // Real openssl output already reads "subject=CN = ..." — the prefix
    // must be stripped before comparing against `cert_issuer`'s output.
    // Found live: comparing the un-stripped strings meant a correctly
    // ordered chain (issuer="issuer=CN = X" vs subject="subject=CN = X")
    // could never match, since the two prefixes always differ.
    let raw = run_openssl(
        &["x509", "-noout", "-subject", "-nameopt", "oneline"],
        cert_pem,
    )?;
    let raw = raw.trim();
    Ok(raw
        .strip_prefix("subject=")
        .unwrap_or(raw)
        .trim()
        .to_string())
}

fn cert_issuer(cert_pem: &str) -> anyhow::Result<String> {
    let raw = run_openssl(
        &["x509", "-noout", "-issuer", "-nameopt", "oneline"],
        cert_pem,
    )?;
    let raw = raw.trim();
    Ok(raw
        .strip_prefix("issuer=")
        .unwrap_or(raw)
        .trim()
        .to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("certmatch: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<bool> {
    match cli.command {
        Command2::CheckPair { cert, key } => {
            let cert_pem = fs::read_to_string(&cert)?;
            let key_pem = fs::read_to_string(&key)?;
            let cert_pub = cert_pubkey(&cert_pem)?;
            let key_pub = key_pubkey(&key_pem)?;
            if keys_match(&cert_pub, &key_pub) {
                println!(
                    "MATCH: {} and {} share the same public key",
                    cert.display(),
                    key.display()
                );
                Ok(true)
            } else {
                println!(
                    "MISMATCH: {} and {} do NOT share the same public key",
                    cert.display(),
                    key.display()
                );
                Ok(false)
            }
        }
        Command2::CheckChain { chain } => {
            let bundle = fs::read_to_string(&chain)?;
            let certs = split_cert_bundle(&bundle);
            if certs.is_empty() {
                anyhow::bail!("no certificates found in {}", chain.display());
            }
            let mut pairs = Vec::new();
            for (i, cert_pem) in certs.iter().enumerate() {
                let subject = cert_subject(cert_pem)?;
                let issuer = cert_issuer(cert_pem)?;
                println!("cert {i}: subject={subject}  issuer={issuer}");
                pairs.push((subject, issuer));
            }
            match chain_order_valid(&pairs) {
                Ok(()) => {
                    println!("chain order: OK ({} certificate(s))", certs.len());
                    Ok(true)
                }
                Err(break_index) => {
                    println!(
                        "chain order: BROKEN at position {break_index} — cert {break_index}'s issuer does not match cert {}'s subject",
                        break_index + 1
                    );
                    Ok(false)
                }
            }
        }
    }
}
