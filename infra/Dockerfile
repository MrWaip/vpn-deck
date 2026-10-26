# sing-box: static Go binary (CGO off), same as upstream release builds, so it
# doesn't depend on the system glibc. Tags: upstream defaults trimmed to what
# the plugin needs (TUN stack, uTLS/REALITY, QUIC-based protocols).
FROM golang:1.25-bookworm AS singbox

ARG SINGBOX_REF=v1.14.4
ARG SINGBOX_TAGS=with_gvisor,with_quic,with_utls,badlinkname,tfogo_checklinkname0

RUN git clone --depth 1 --branch "${SINGBOX_REF}" https://github.com/SagerNet/sing-box.git /src/sing-box
WORKDIR /src/sing-box
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=auto go build -trimpath -tags "${SINGBOX_TAGS}" \
        -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${SINGBOX_REF#v}' $(cat release/LDFLAGS) -s -w -buildid=" \
        -o /sing-box ./cmd/sing-box

FROM ghcr.io/steamdeckhomebrew/holo-base:latest

RUN pacman -Sy --noconfirm && \
    pacman -S --noconfirm go git base-devel libmnl && \
    pacman -Scc --noconfirm

ARG AMNEZIAWG_GO_REF=v3.1.20260828
ARG AMNEZIAWG_TOOLS_REF=v3.1.20260812

RUN git clone --depth 1 --branch "${AMNEZIAWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go.git /tmp/amneziawg-go && \
    make -C /tmp/amneziawg-go

RUN git clone --depth 1 --branch "${AMNEZIAWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/amneziawg-tools && \
    make -C /tmp/amneziawg-tools/src

COPY --from=singbox /sing-box /tmp/sing-box

RUN mkdir /binaries && \
    cp /tmp/amneziawg-go/amneziawg-go /binaries/ && \
    cp /tmp/amneziawg-tools/src/wg /binaries/awg && \
    cp /tmp/sing-box /binaries/sing-box
