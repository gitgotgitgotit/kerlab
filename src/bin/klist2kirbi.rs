extern crate clap;
extern crate kerlab;
extern crate regex;

use clap::{App, Arg};
use std::fs;
use std::fs::File;
use kerlab::krbcred::{KrbCred};
use kerlab::asn1::{from_ber, to_der, GeneralString, OctetString};
use kerlab::display::{Formatter, Display};
use kerlab::ticket::{Ticket};
use std::io::{Write};
use kerlab::base::{PrincipalName, PrincipalNameType};
use kerlab::krbkdcrep::{EncKDCRepPart};
use std::str::FromStr;
use kerlab::encryption::EType;
use regex::Regex;

const APPLICATION_NAME: &str = "klist2kirbi";

fn main() {
    let matches = App::new(APPLICATION_NAME)
        .version("0.1.0")
        .author("cert@airbus.com")
        .about("Kerberos Lab for Fun and Detection")
        .arg(Arg::with_name("klist")
            .long("klist")
            .takes_value(true)
            .help("Path to file that contain the klist output"))
        .arg(Arg::with_name("outfile")
            .long("outfile")
            .takes_value(true)
            .help("Output kirbi file path"))
        .get_matches();

    let contents = fs::read_to_string(
        matches.value_of("klist")
            .expect("klist argument is mandatory")
    ).unwrap();

    let mut client_name = None;
    let mut service_name = None;
    let mut domain_name = None;
    let mut session_key = None;
    let mut session_key_type = None;
    let mut ticket_data = None;
    let mut ticket_flags = None;

    let reg_servicename = Regex::new(r"ServiceName\s+: (?<servicename>[^\r\n]+)\r?\n").unwrap();

    if let Some(caps) = reg_servicename.captures(&contents) {
        service_name = Some(caps["servicename"].to_string());
    };

    let reg_domainname = Regex::new(r"DomainName\s+: (?<domainname>[^\r\n]+)\r?\n").unwrap();

    if let Some(caps) = reg_domainname.captures(&contents) {
        domain_name = Some(caps["domainname"].to_string());
    };

    let reg_clientname = Regex::new(r"ClientName\s+: (?<clientname>[^\r\n]+)\r?\n").unwrap();

    if let Some(caps) = reg_clientname.captures(&contents) {
        client_name = Some(caps["clientname"].to_string());
    };

    let reg_session_key = Regex::new(r"Session Key\s+: KeyType 0x(?<keytype>\d{2}) - (?<keytypename>[a-zA-Z0-9\-]+)\r?\n\s+: KeyLength (?<keylength>\d\d) - (?<sessionkey>[^\r\n]+)\r?\n").unwrap();

    if let Some(caps) = reg_session_key.captures(&contents) {
        session_key = Some(hex::decode(caps["sessionkey"].replace(" ", "")).unwrap());
        session_key_type = match &caps["keytypename"] {
            "AES-256-CTS-HMAC-SHA1-96" => Some(EType::Aes256CtsHmacSha196),
            _ => None
        }
    };

    let reg_encoded_ticket = Regex::new(r"EncodedTicket\s+: \(size: (?<encoded_tiket_size>\d+)\)\r?\n(?<encodedticket>([a-z0-9]{4}  ([a-zA-Z0-9]{2}(\s|:))+\s[^\n]+\n)+)").unwrap();

    if let Some(caps) = reg_encoded_ticket.captures(&contents) {
        let reg_encoded_ticket = Regex::new(r"[a-z0-9]{4}  (?<ticket_part>([a-zA-Z0-9]{2}(\s|:))+\s)").unwrap();
        let ticket_raw_data : Vec<String> = reg_encoded_ticket.captures_iter(&caps["encodedticket"]).map(|caps| {
            let (_, [a, _, _]) = caps.extract();
            a.replace(":" ," ").replace(" ", "")
        }).collect();

        let data = hex::decode(ticket_raw_data.join("")).unwrap();
        if data.len() != caps["encoded_tiket_size"].parse::<usize>().unwrap() {
            println!("Invalid ticket size!");
            return;
        }
        ticket_data = Some(data)
    };

    let reg_ticket_flags = Regex::new(r"Ticket Flags\s+: 0x(?<ticket_flags>[a-zA-Z0-9]+)").unwrap();

    if let Some(caps) = reg_ticket_flags.captures(&contents) {
        ticket_flags = Some(u32::from_str_radix(&caps["ticket_flags"], 16).unwrap());
    };

    let mut ticket = Ticket::default();
    from_ber(&mut ticket, &ticket_data.expect("Unable to parse Encoded Ticket data from klist output")).unwrap();

    let t = KrbCred::new(
        PrincipalName::new(PrincipalNameType::NtPrincipal, vec![GeneralString::from_str(&client_name.expect("Unable to parse ClientName from klist output")).unwrap()]),
        ticket,
        EncKDCRepPart::new(
            session_key_type.expect("Unable to parse Session Key Type from klist output"),
            OctetString::from(session_key.expect("Unable to parse session key from klist output")),
            &domain_name.expect("Unable to parse DomainName from klist output"),
            &service_name.expect("Unable to parse ServiceName from klist output"),
            ticket_flags.expect("Unable to parse Ticket Flags from klist output"),
        ).unwrap()
    ).unwrap();

    t.format(&mut Formatter::new());

    if let Some(path) = matches.value_of("outfile") {
        let mut file = File::create(path).unwrap();
        file.write_all(&to_der(&t)).unwrap();

        println!("**************************************************");
        println!("Saving KRB-CRED in {}", path);
    }
}