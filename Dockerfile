# Run "Mnemonic Shamir Secret Sharing Tool" in Docker
# More info: https://github.com/ava-labs/mnemonic-shamir-secret-sharing-cli


##### How to use:
# - start docker daemon
# - `cd` to this directory, then:

### build image once
# docker build -t msss .
### run container
# docker run -it --rm msss

### use tool - see also https://github.com/ava-labs/mnemonic-shamir-secret-sharing-cli
# msss
# msss generate
# msss split -quorum 3 -total 7 -word long -mode phrase
# msss recover -quorum 3 -word long -mode phrase
# exit


##### Dockerfile

# Download base image ubuntu
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt upgrade -y

# Install from ubuntu repository
RUN apt install -y git libssl-dev make clang-14
RUN rm -rf /var/lib/apt/lists/*
RUN apt clean

RUN ln -s /usr/bin/clang-14 /usr/bin/clang
RUN ln -s /usr/bin/clang++-14 /usr/bin/clang++

# Install and build Mnemonic Shamir Secret Sharing repo
RUN git clone https://github.com/ava-labs/mnemonic-shamir-secret-sharing-cli msss
WORKDIR /msss/MnemonicShamirCLI
RUN make

RUN chmod +x build/mnemonic-sss
RUN ln -s build/mnemonic-sss mnemonic-sss
RUN ln -s build/mnemonic-sss m-sss
RUN ln -s build/mnemonic-sss sss
RUN ln -s build/mnemonic-sss msss
ENV PATH="${PATH}:/msss/MnemonicShamirCLI"
