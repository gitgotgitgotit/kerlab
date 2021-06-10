extern crate clap;
extern crate kerlab;

use clap::{App, Arg, ArgMatches};
use std::fs;
use kerlab::krbcred::{KrbCred, EncKrbCredPart};
use kerlab::asn1::{from_ber};
use kerlab::display::{Formatter, Display};
use kerlab::encryption::{EType, EncryptedData, EncryptionKey, KeyUsage};
use kerlab::ticket::EncTicketPart;
use std::fs::File;
use std::io::{Write};
use kerlab::error::{Error, KerlabErrorKind, KerlabResult};
use std::convert::TryFrom;

const APPLICATION_NAME: &str = "kerticket";

fn generate_encryption_key_from_encryped_data(encrypted_data: &EncryptedData, matches: &ArgMatches) -> KerlabResult<EncryptionKey> {
    match EType::try_from(encrypted_data.etype.inner)? {
        EType::NoEncryption => {
            EncryptionKey::new_no_encryption()
        },
        EType::Rc4Hmac => {
            if let Some(ntlm) = matches.value_of("key") {
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
            if let Some(aes) = matches.value_of("key") {
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
            if let Some(aes) = matches.value_of("key") {
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
        .arg(Arg::with_name("ticket")
            .long("ticket")
            .takes_value(true)
            .help("Path to the ticket file"))
        .arg(Arg::with_name("key")
            .long("key")
            .takes_value(true)
            .help("Raw key (NTLM Hashes, AES key)"))
        .arg(Arg::with_name("domain")
            .long("domain")
            .takes_value(true)
            .help("Use to decrypt the ticket in AES mode with password"))
        .arg(Arg::with_name("username")
            .long("username")
            .takes_value(true)
            .help("Use to decrypt the ticket in AES mode with password"))
        .arg(Arg::with_name("password")
            .long("password")
            .takes_value(true)
            .help("Password to decrypt ticket"))
        .arg(Arg::with_name("hashcat")
            .long("hashcat")
            .takes_value(true)
            .help("output file for hash cat brute forcing"))
        .get_matches();

    // load ticket info from tgt
    let contents = fs::read(
        matches.value_of("ticket")
            .expect("ticket argument is mandatory")
    ).unwrap();

    let mut ticket = KrbCred::default();
    from_ber(&mut ticket, &contents).unwrap();

    println!("*******************************************");
    println!("KRB-CRED := ");
    ticket.format(&mut Formatter::new());

    println!("*******************************************");
    println!("Decrypting KRB-CRED.enc_part");
    println!("EncKrbCredPart := ");
    let mut body = EncryptionKey::new_no_encryption().unwrap()
        .decrypt::<EncKrbCredPart>(
            KeyUsage::KeyUsageAsRepEncPart,
            &ticket.enc_part,
        ).unwrap();
    body.format(&mut Formatter::new());


    let tgs_info = body.ticket_info.pop().unwrap();
    let tgs = ticket.tickets.pop().unwrap();

    let  key = generate_encryption_key_from_encryped_data(&tgs.enc_part, &matches);
    let sname = tgs_info.sname.unwrap().name_string.iter().map(|x| String::from(x.as_str())).collect::<Vec<String>>().join("/");
    println!("**************************************************");
    println!("Trying to decrypt the first ticket.enc-part");
    println!("EncTicketPart := ");
    match key {
        Ok(key) => {
            let ticket_enc_part = key.decrypt::<EncTicketPart>(
                KeyUsage::KeyUsageAsRepTicket,
                &tgs.enc_part,
            ).unwrap();
            ticket_enc_part.format(&mut Formatter::new());
        }
        Err(e) => {
            println!("Unable to decrypt : {:?}.", e);
            println!("You need to provide the key of {} service account.", sname)
        }
    }

    println!("**************************************************");

    if let Some(hashcat) = matches.value_of("hashcat") {
        let mut file = File::create(hashcat).unwrap();
        file.write_all(format!("$krb5tgs${0}$*{1}${2}${3}*${4}${5}",
                tgs.enc_part.etype.inner,
                tgs_info.pname.unwrap().name_string[0],
                tgs_info.srealm.unwrap().as_str(), sname,
                hex::encode(&tgs.enc_part.cipher.inner[0..16]),
                hex::encode(&tgs.enc_part.cipher.inner[16..]
            )
        ).as_bytes()).unwrap();
    }
}