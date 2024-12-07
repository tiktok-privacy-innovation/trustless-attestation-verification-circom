FROM node:22

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install required build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    git

RUN apt-get install -y \
    curl \
    wget \
    libssl-dev \
    pkg-config \
    ca-certificates

# Install Rust 1.81.0 using rustup
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain 1.81.0

# Set environment variables for Rust
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust installation
RUN rustc --version

# Install Circom 2.1.9
RUN git clone https://github.com/iden3/circom.git && \
    cd circom && \
    git checkout tags/v2.1.9 && \
    cargo build --release && \
    cargo install --path circom && \
    cd / && \
    rm -rf circom

# Install snarkjs globally using npm
RUN npm install -g snarkjs

# Set the working directory
WORKDIR /app

CMD ["/bin/bash"]
