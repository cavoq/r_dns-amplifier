FROM rust:1.81.0

RUN apt-get update && \
    apt-get install -y \
    libpcap-dev \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /r_dns-amplifier

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

ENTRYPOINT ["./target/release/r_dns-amplifier"]
