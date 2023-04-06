// DNS Amplification Script
// Author: David Stromberger
// License: MIT
// Version: 1.0
// Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.

use reqwest;
use tokio;

async fn get_public_dns_servers(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?.text().await?;
    let servers = response.lines().map(|s| s.trim().to_string()).collect();
    Ok(servers)
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let servers = get_public_dns_servers("https://public-dns.info/nameservers.txt").await?;

    println!("{} DNS servers found:", servers.len());
    for server in servers {
        println!("{}", server);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await?;
    Ok(())
}
