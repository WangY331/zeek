# See the file "COPYING" in the main distribution directory for copyright.

# Layer to build Zeek.
FROM debian:bullseye-slim

RUN echo 'Acquire::Retries "3";' > /etc/apt/apt.conf.d/80-retries

# Configure system for build.
RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     bind9 \
     bison \
     ccache \
     cmake \
     flex \
     g++ \
     gcc \
     libfl2 \
     libfl-dev \
     libmaxminddb-dev \
     libpcap-dev \
     libssl-dev \
     libz-dev \
     make \
     python3-minimal \
     python3.9-dev \
     swig \
     ninja-build \
     python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
