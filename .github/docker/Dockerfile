FROM ubuntu:24.04

# Prevent interactive prompts during apt-get install
ENV DEBIAN_FRONTEND=noninteractive

# Install all build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    dkms \
    dpkg-dev \
    devscripts \
    debhelper \
    linux-headers-generic \
    git \
    jq \
    wget \
    rapidjson-dev \
    libssl-dev \
    libncurses-dev \
    libboost-program-options-dev \
    libboost-filesystem-dev \
    libboost-dev \
    ocl-icd-opencl-dev \
    libdrm-dev \
    pkg-config \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
