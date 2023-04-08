# r_dns-amplifier

![license](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![version](https://img.shields.io/badge/version-0.1.0-lightgrey.svg)

`r_dns-amplifier` is a Rust script that performs DNS amplification attacks. It sends DNS queries to a target server with a spoofed source IP address, causing the target server to send a large amount of DNS response data to the spoofed IP address, thus amplifying the traffic. Please note that performing DNS amplification attacks is illegal and can cause harm to innocent parties. This code is provided for educational purposes only and should not be used for any malicious activities. The author of this code is not responsible for any harm caused by the misuse of this code.

## Disclaimer

Performing DNS amplification attacks is illegal and can cause harm to innocent parties. This code is provided for educational purposes only and should not be used for any malicious activities. The author of this code is not responsible for any harm caused by the misuse of this code.

## Requirements

The script requires Rust to be installed.

## Install

You can install the script globally using the cargo package manager by running:

```
cargo install --git https://github.com/Dav3o/r_dns-amplifier.git --branch master
```

Because this script uses raw sockets it requires root privileges, you need to set an alias and run the script like this if you don't want
to specify the full path:

```
echo "alias sudo-rdns='sudo env \"PATH=$PATH\" r_dns-amplifier'" >> ~/.bashrc && source ~/.bashrc
```

**Note that insteas of *r_dns-amplifier* you call *sudo-rdns***
## Usage

Example usage with global install:
```
sudo-rdns 192.168.2.1 80 -r ANY -d google.com
```

You can also run this script by building it directly after cloning:
```
cargo build --release
```

![Screenshot from 2023-04-08 14-14-40](https://user-images.githubusercontent.com/61215846/230720615-7ca0c1fd-c641-4129-a8c4-1af913edab3e.png)
