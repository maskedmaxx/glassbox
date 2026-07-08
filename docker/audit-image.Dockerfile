FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        dnsutils \
        findutils \
        git \
        iproute2 \
        jq \
        netbase \
        procps \
        python3 \
        tar \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["bash"]
