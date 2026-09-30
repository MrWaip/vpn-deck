FROM golang:1.26 AS sing-box

ARG SING_BOX_REF=v1.14.2

# Upstream release flags with a trimmed tag set: VLESS/REALITY need uTLS, gvisor serves the mixed TUN stack.
RUN git clone --depth 1 --branch "${SING_BOX_REF}" https://github.com/SagerNet/sing-box.git /tmp/sing-box && \
    cd /tmp/sing-box && \
    CGO_ENABLED=0 go build -trimpath \
        -tags with_gvisor,with_utls,badlinkname,tfogo_checklinkname0 \
        -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${SING_BOX_REF#v}' $(cat release/LDFLAGS) -s -w -buildid=" \
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

RUN mkdir /binaries && \
    cp /tmp/amneziawg-go/amneziawg-go /binaries/ && \
    cp /tmp/amneziawg-tools/src/wg /binaries/awg

COPY --from=sing-box /sing-box /binaries/sing-box
