# DMTI

Dynamic Memory Tagging Instrumentation

This repository contains the prototype presented in:

Andreas Hager-Clukas and Konrad Hohentanner, “DMTI: Accelerating Memory Error Detection in Precompiled C/C++ Binaries with ARM Memory Tagging Extension,” in *Proceedings of the 19th ACM Asia Conference on Computer and Communications Security (ASIA CCS '24)*, pages 1173–1185, 2024.

Paper PDF: https://dl.acm.org/doi/pdf/10.1145/3634737.3637655

## Quickstart with Docker

The recommended way to build and run DMTI is with Docker. This avoids manual installation of QEMU, DynamoRIO, and the required build dependencies on the host.

### Requirements

- Docker

## Build the Docker image
Build the image from the repository root:

```console
docker build -t dmti .
```

## Start the container

Run the container and open a shell inside it:

```console
docker run --rm -it dmti:latest /bin/bash
```

## Build DMTI inside the container
Inside the container, build the instrumentation tool:

```console
cd /work/DMTI
bash ./instrumentation/build.sh
```

## Run the examples

Run the examples inside the container with:

```console
/work/DMTI/instrumentation/examples/bax.sh
```

## Repository layout
0001-tg-changes.patch: patch applied to QEMU

0001-target-arm-adjust-MTE-handling-for-TG-mode.patch: patch applied to DynamoRIO

instrumentation/: DMTI instrumentation sources

examples/: example binaries and analysis JSON files