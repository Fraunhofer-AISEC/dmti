FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    curl \
    wget \
    file \
    libcjson-dev \
    build-essential \
    pkg-config \
    python3 \
    python3-pip \
    ninja-build \
    cmake \
    clang \
    lld \
    llvm \
    openjdk-17-jdk \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    libglib2.0-dev \
    libpixman-1-dev \
    zlib1g-dev \
    libcapstone-dev \
    libelf-dev \
    unzip \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work/DMTI
COPY . .

ARG QEMU_REPO="https://github.com/qemu/qemu.git"
ARG QEMU_REF="6cb2011fedf8c4e7b66b4a3abd6b42c1bae99ce6"

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /src
RUN git clone "${QEMU_REPO}" qemu
WORKDIR /src/qemu
RUN git checkout "${QEMU_REF}" \
 && git config user.email "docker@local" \
 && git config user.name "Docker Build"
RUN (git am /work/DMTI/0001-target-arm-adjust-MTE-handling-for-TG-mode.patch) || (git am --abort || true; git apply --index --whitespace=nowarn /work/DMTI/0001-target-arm-adjust-MTE-handling-for-TG-mode.patch)

ARG DR_REPO="https://github.com/DynamoRIO/dynamorio.git"
ARG DR_REF="4e41da314d7f593be3b0a3d3282cba1832a99228"

WORKDIR /src
RUN git clone "${DR_REPO}" dynamorio
WORKDIR /src/dynamorio
RUN git checkout "${DR_REF}" \
 && git config user.email "docker@local" \
 && git config user.name "Docker Build"
RUN (git am /work/DMTI/0001-dynamorio-changes.patch) || (git am --abort || true; git apply --index --whitespace=nowarn /work/DMTI/0001-dynamorio-changes.patch)

RUN cd /tmp \
 && wget https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz \
 && tar -xzf v1.7.15.tar.gz \
 && cd cJSON-1.7.15 \
 && mkdir build \
 && cd build \
 && cmake -G Ninja \
      -DCMAKE_INSTALL_PREFIX=/usr/aarch64-linux-gnu \
      -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
      -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
      .. \
 && ninja \
 && ninja install \
 && cd / \
 && rm -rf /tmp/cJSON-1.7.15 /tmp/v1.7.15.tar.gz

ARG GHIDRA_VERSION="10.3.2"
ARG GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_20230711.zip"
ARG GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"

RUN cd /opt \
 && wget -O "${GHIDRA_ZIP}" "${GHIDRA_URL}" \
 && unzip "${GHIDRA_ZIP}" \
 && rm "${GHIDRA_ZIP}"

WORKDIR /src/dynamorio
RUN mkdir -p build_aarch64 \
 && cd build_aarch64 \
 && cmake -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=../make/toolchain-aarch64.cmake \
      .. \
 && ninja

WORKDIR /src/qemu
RUN rm -rf build \
 && mkdir -p build \
 && cd build \
 && ../configure --target-list=aarch64-linux-user \
 && test -f build.ninja \
 && ninja

RUN cp /work/DMTI/analysis/MetaMem.java /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Processors/JVM/ghidra_scripts/MetaMem.java

WORKDIR /work/DMTI