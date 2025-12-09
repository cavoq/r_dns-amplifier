# 🔊 r_dns-amplifier

![license](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![version](https://img.shields.io/badge/version-2.6.0-lightgrey.svg)

A Rust tool for **educational purposes** to demonstrate DNS amplification attacks. It sends spoofed DNS queries to a target server, which then responds with a large volume of data to the specified address, amplifying the traffic.

> ⚠️ **DISCLAIMER:** DNS amplification attacks are illegal and unethical. Use this tool responsibly and only for educational purposes. The author disclaims all responsibility for misuse.

## 🛠️ Requirements

- Rust (tested with version 1.81.0)
- Additional libraries: `pkg-config`, `libssl-dev`

## 📦 Installation

Install globally via Cargo:

```bash
cargo install --git https://github.com/cavoq/r_dns-amplifier.git --branch master
```

You may also need some additional libs:

```bash
sudo apt-get install pkg-config libssl-dev
```

Because this script uses raw sockets it requires root privileges. Set an alias to avoid specifying the full path:

```bash
echo "alias sudo-rdns='sudo env \"PATH=$PATH\" r_dns-amplifier'" >> ~/.bashrc && source ~/.bashrc
```

> 💡 **Note:** Instead of `r_dns-amplifier` you call `sudo-rdns`

## 🚀 Usage

Example usage with global install:

```bash
sudo-rdns 192.168.2.1 --port 53 -r ANY -d google.com
```

You can also run this script by building it directly after cloning:

```bash
cargo build --release
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `<TARGET>` | IPv4 address of the target | *required* |
| `-p, --port` | Port of the target | `53` |
| `-r, --record-type` | DNS record type [A, MX, NS, ANY] | `ANY` |
| `-s, --server-list` | List of DNS servers to use | - |
| `-t, --time` | Time of the attack in seconds | - |
| `-d, --domain` | Domain to resolve | `google.com` |
| `-m, --threads` | Thread count | `10` |
| `-n, --dns-resolver` | DNS resolver to use | - |

## 🐳 Docker

Run in a Docker container (the `--privileged` flag is required for raw sockets):

```bash
docker build -t r_dns-amplifier .
docker run --rm --privileged r_dns-amplifier 192.168.2.1 --port 53 -r ANY -d google.com
```
