extern crate kerlab;
extern crate clap;

use kerlab::krbkdcreq::{AsReq, KdcOptionsType};
use kerlab::asn1::to_der;
use std::io::{Write};
use kerlab::display::{Display, Formatter};
use kerlab::request::{KrbResponse, TcpRequest};
use kerlab::krbkdcrep::{AsRep, EncASRepPart};
use clap::{App, Arg, ArgMatches};
use kerlab::encryption::{KeyUsage, EncryptionKey, EncryptedData, EType};
use std::fs::File;
use kerlab::error::{Error, KerlabErrorKind, KerlabResult};
use kerlab::krbcred::KrbCred;
use std::convert::TryFrom;

const APPLICATION_NAME: &str = "kerasktgt";


fn generate_encryption_key_from_paramater(matches: &ArgMatches) -> KerlabResult<EncryptionKey> {
    if let Some(password) = matches.value_of("password") {
        match matches.value_of("etype").unwrap() {
            "aes256" => {
                EncryptionKey::new_aes256_hmac(
                    matches.value_of("domain").expect("domain is mandatory to create key"),
                    matches.value_of("username").expect("username is mandatory to create key"),
                    password
                )
            },
            "aes128" => {
                EncryptionKey::new_aes128_hmac(
                    matches.value_of("domain").expect("domain is mandatory to create key"),
                    matches.value_of("username").expect("username is mandatory to create key"),
                    password
                )
            },
            "rc4" => {
                EncryptionKey::new_rc4_hmac(
                    password
                )
            },
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Invalid etype mode"))
        }

    }
    else if let Some(ntlm) = matches.value_of("ntlm") {
        EncryptionKey::new_rc4_hmac_from_hash(hex::decode(ntlm).unwrap())
    }
    else if let Some(aes128) = matches.value_of("aes128") {
        EncryptionKey::new_aes128_hmac_from_aeskey(hex::decode(aes128).unwrap())
    }
    else if let Some(aes256) = matches.value_of("aes256") {
        EncryptionKey::new_aes256_hmac_from_aeskey(hex::decode(aes256).unwrap())
    }
    else {
        Err(Error::new(KerlabErrorKind::Crypto, "No encryption key"))
    }
}

fn generate_encryption_key_from_encryped_data(encrypted_data: &EncryptedData, matches: &ArgMatches) -> KerlabResult<EncryptionKey> {
    match EType::try_from(encrypted_data.etype.inner)? {
        EType::NoEncryption => {
            EncryptionKey::new_no_encryption()
        },
        EType::Rc4Hmac => {
            if let Some(ntlm) = matches.value_of("ntlm") {
                EncryptionKey::new_rc4_hmac_from_hash(hex::decode(ntlm).unwrap())
            }
            else if let Some(password) = matches.value_of("password") {
                EncryptionKey::new_rc4_hmac(password)
            }
            else {
                Err(Error::new(KerlabErrorKind::Crypto, "Not enough material to decrypt the encrypted data"))
            }
        },
        EType::Aes128CtsHmacSha196 => {
            if let Some(aes) = matches.value_of("aes128") {
                EncryptionKey::new_aes128_hmac_from_aeskey(hex::decode(aes).unwrap())
            }
            else if let (Some(domain), Some(username), Some(password)) = (matches.value_of("domain"), matches.value_of("username"), matches.value_of("password")) {
                EncryptionKey::new_aes128_hmac(domain, username, password)
            }
            else {
                Err(Error::new(KerlabErrorKind::Crypto, "Not enough material to decrypt the encrypted data"))
            }
        },
        EType::Aes256CtsHmacSha196 => {
            if let Some(aes) = matches.value_of("aes256") {
                EncryptionKey::new_aes256_hmac_from_aeskey(hex::decode(aes).unwrap())
            }
            else if let (Some(domain), Some(username), Some(password)) = (matches.value_of("domain"), matches.value_of("username"), matches.value_of("password")) {
                EncryptionKey::new_aes256_hmac(domain, username, password)
            }
            else {
                Err(Error::new(KerlabErrorKind::Crypto, "Not enough material to decrypt the encrypted data"))
            }
        },
        _ => Err(Error::new(KerlabErrorKind::Crypto, "Not enough materials to decrypt the encrypted data"))
    }
}

fn main() {

    let matches = App::new(APPLICATION_NAME)
        .version("0.1.0")
        .author("Sylvain Peyrefitte <citronneur@gmail.com>")
        .about("Kerberos Lab for Fun and Detection")
        .arg(Arg::with_name("dc")
             .long("dc")
             .takes_value(true)
             .help("host IP of the Domain Controller"))
        .arg(Arg::with_name("port")
             .long("port")
             .takes_value(true)
             .default_value("88")
             .help("Domain Controller Kerberos port"))
        .arg(Arg::with_name("domain")
             .long("domain")
             .takes_value(true)
             .help("Windows Domain"))
        .arg(Arg::with_name("username")
             .long("username")
             .takes_value(true)
             .help("Username of TGT"))
        .arg(Arg::with_name("password")
             .long("password")
             .takes_value(true)
             .help("Username password"))
        .arg(Arg::with_name("ntlm")
             .long("ntlm")
             .takes_value(true)
             .help("NTLM hash for RC4 encryption"))
        .arg(Arg::with_name("aes256")
            .long("aes256")
            .takes_value(true)
            .help("AES 256 user key"))
        .arg(Arg::with_name("aes128")
            .long("aes128")
            .takes_value(true)
            .help("AES 128 user key"))
        .arg(Arg::with_name("outfile")
             .long("outfile")
             .takes_value(true)
             .help("Output file path"))
        .arg(Arg::with_name("forwardable")
             .long("forwardable")
             .help("Ask for a forwardable ticket"))
        .arg(Arg::with_name("renewable")
             .long("renewable")
             .help("Ask for a renewable ticket"))
        .arg(Arg::with_name("etype")
            .long("etype")
            .help("force using particular crypto algorithm")
            .possible_values(&["rc4", "aes128", "aes256"])
            .default_value("aes256")
        )
        .get_matches();

    let ip = matches.value_of("dc").expect("You need to provide a dc argument");
    let port = matches.value_of("port").unwrap_or_default();

    // compute options
    let mut options = vec![];
    if matches.is_present("renewable") {
        options.push(KdcOptionsType::Renewable);
        options.push(KdcOptionsType::RenewableOk);
    }

    if matches.is_present("forwardable") {
        options.push(KdcOptionsType::Forwardable);
    }

    let domain = matches.value_of("domain").expect("You need to provide a domain argument");
    let username = matches.value_of("username").expect("You need to provide a password argument");

    // create request
    let mut tgt_request = AsReq::new(
        domain,
        username,
        &options,
        None
    ).unwrap();

    // If there is enough material to generate preauth let's go
    // or we will try without preauth
    if let Ok(encryption_key) = generate_encryption_key_from_paramater(&matches) {
        tgt_request = tgt_request.with_preauth(
            &encryption_key
        ).unwrap();
    }

    println!("**************************************************");
    println!("AS-REQ ::=");
    tgt_request.format(&mut Formatter::new());

    let tgt_response = TcpRequest::ask_for::<AsRep, String>(&tgt_request, format!("{}:{}", ip, port)).unwrap();

    match tgt_response {
        KrbResponse::Error(error) => {
            println!("**************************************************");
            println!("KRB-ERROR ::=");
            error.format(&mut Formatter::new());
        }
        KrbResponse::Response(response) => {
            println!("**************************************************");
            println!("AS-REP ::=");
            response.format(&mut Formatter::new());


            let key = generate_encryption_key_from_encryped_data(&response.enc_part, &matches).unwrap();

            println!("**************************************************");
            println!("Decrypting the KDC-REP.enc-part");
            let enc_part = key.decrypt::<EncASRepPart>(
                    match EType::try_from(key.keytype.inner).unwrap() {
                        EType::Aes128CtsHmacSha196 | EType::Aes256CtsHmacSha196 => KeyUsage::KeyUsageAsRepEncPart1,
                        _ => KeyUsage::KeyUsageAsRepEncPart
                    },
                    &response.enc_part
                ).unwrap();

            enc_part.format(&mut Formatter::new());

            if let Some(path) = matches.value_of("outfile") {
                let mut file = File::create(path).unwrap();
                let credentials = KrbCred::new(
                    response.cname.inner.clone(),
                    response.ticket.inner.clone(),
                    enc_part.inner
                ).unwrap();
                file.write_all(&to_der(&credentials)).unwrap();

                println!("**************************************************");
                println!("Saving KRB-CRED in {}", path);
            }

        }
    }
    println!("**************************************************");
}