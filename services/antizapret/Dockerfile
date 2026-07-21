FROM golang:1.26 AS builder-api
WORKDIR /app
COPY ./api/go.* .
RUN go mod download
COPY ./api .
RUN go build -o app

FROM golang:1.26 AS builder-compose2swarm
WORKDIR /app
COPY ./compose2swarm/go.* .
RUN go mod download
COPY ./compose2swarm .
RUN go build -o compose2swarm

FROM golang:1.26 AS builder-routes
WORKDIR /app
COPY ./routes/go.* .
RUN go mod download
COPY ./routes .
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w -s -extldflags "-static"' -o routes

FROM golang:1.26 AS builder-dnsmap
ARG TARGETARCH
WORKDIR /app
COPY ./dnsmap/go.mod ./dnsmap/go.sum ./
RUN go mod download
COPY ./dnsmap .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags '-w -s' -o dnsmap ./cmd/dnsmap

FROM debian:trixie-slim

WORKDIR /root

RUN <<-"EOT" bash -ex
    APT_LISTCHANGES_FRONTEND=none
    DEBIAN_FRONTEND=noninteractive

    apt-get update -q
    apt-get install -qqy --no-install-suggests --no-install-recommends \
        bash \
        gzip \
        iperf3 \
        curl \
        ca-certificates \
        dnsutils \
        gawk \
        inetutils-ping \
        ipset \
        iptables \
        nftables \
        iproute2 \
        ipcalc \
        moreutils \
        procps \
        sipcalc
    apt-get clean
    rm -frv /var/lib/apt/lists/*
EOT

RUN mkdir -p /usr/share/GeoIP && \
    curl -fL --retry 3 -o /usr/share/GeoIP/GeoLite2-ASN.mmdb \
        https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb

COPY --from=builder-api /app/app /opt/api/app
COPY --from=builder-compose2swarm /app/compose2swarm /usr/bin/compose2swarm
COPY --from=builder-routes /app/routes /usr/bin/routes
COPY --from=builder-dnsmap /app/dnsmap /usr/bin/dnsmap
COPY --from=vernette/ss-zapret2:v1.0.2 /opt/zapret2/ /opt/zapret2/
COPY . /

RUN <<-"EOF" bash -ex
    for list in antizapret/config/*-custom.txt; do rm -f $list; done

    cp -a /opt/zapret2/lua.dist /opt/zapret2/lua
    cp -a /opt/zapret2/files/fake.dist /opt/zapret2/files/fake

    ln -sf /root/antizapret/doall.sh /usr/bin/doall
    rm -frv /dnsmap

    rm -frv /tmp/*
EOF

CMD ["/init.sh"]
