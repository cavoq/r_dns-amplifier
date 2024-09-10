# r_dns-amplifier

![license](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![version](https://img.shields.io/badge/version-2.6.0-lightgrey.svg)

`r_dns-amplifier` is a Rust tool for educational purposes to demonstrate DNS amplification attacks. It sends spoofed DNS queries to a target server, which then responds with a large volume of data to the specified address, amplifying the traffic.

**DISCLAIMER:** DNS amplification attacks are illegal and unethical. Use this tool responsibly and only for educational purposes. The author disclaims all responsibility for misuse.

## Requirements

- Rust (tested with version 1.81.0)
- Additional libraries: `pkg-config`, `libssl-dev`

## Install

Install globally via Cargo:

## Install

You can install the script globally using the cargo package manager by running:

```
cargo install --git https://github.com/cavoq/r_dns-amplifier.git --branch master
```

You may also need some additional libs:

```
sudo apt-get install pkg-config libssl-dev
```

Because this script uses raw sockets it requires root privileges, you need to set an alias and run the script like this if you don't want
to specify the full path:

```
echo "alias sudo-rdns='sudo env \"PATH=$PATH\" r_dns-amplifier'" >> ~/.bashrc && source ~/.bashrc
```

**Note: Instead of *r_dns-amplifier* you call *sudo-rdns***
## Usage

Example usage with global install:
```
sudo-rdns 192.168.2.1 --port 53 -r ANY -d google.com
```

You can also run this script by building it directly after cloning:
```
cargo build --release
```

*see help:*

```
Usage: r_dns-amplifier [OPTIONS] <TARGET>

Arguments:
  <TARGET>  IPv4 address of the target

Options:
  -p, --port <PORT>                  Port of the target [default: 53]
  -r, --record-type <RECORD_TYPE>    DNS record type to use [A, MX, NS, ANY] [default: ANY]
  -s, --server-list <SERVER_LIST>    List of DNS servers to use
  -t, --time <TIME>                  Time of the attack in seconds
  -d, --domain <DOMAIN>              Domain to resolve [default: google.com]
  -m, --threads <THREADS>            Thread count [default: 10]
  -n, --dns-resolver <DNS_RESOLVER>  DNS resolver to use
  -h, --help                         Print help
  -V, --version                      Print version
```

## Docker

You can also run this script in a Docker container, the `--privileged` flag is required to use raw sockets in the container.

```
docker build -t r_dns-amplifier .
docker run --rm --privileged r_dns-amplifier 192.168.2.1 --port 53 -r ANY -d google.com
```
