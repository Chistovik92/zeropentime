#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# NAT-стенд: настоящие TUN-интерфейсы и NAT на Linux network namespaces.
#
#   zhostA (10.0.1.2) -- znatA [NAT] --+
#                                      +-- zwan: контроллер + STUN (198.51.100.10)
#   zhostB (10.0.2.2) -- znatB [NAT] --+
#
# NAT-роутеры — nftables masquerade: обычный режим ведёт себя как конусный
# NAT (порт сохраняется), fully-random — как симметричный, udp-blocked —
# конусный NAT, который не выпускает UDP (только TCP: VLESS + REALITY).
#
# Запуск (нужен root): sudo bash test/natlab/run.sh КАТАЛОГ_С_БИНАРНИКАМИ
set -Eeuo pipefail
export PS4='+ ${LINENO}: '
[ -n "${NATLAB_TRACE:-}" ] && set -x

BIN=$(realpath "${1:?укажите каталог с zpt и zpt-controller}")
WORK=${NATLAB_WORK:-/tmp/natlab}
CTRL_IP=198.51.100.10
CTRL_URL="http://$CTRL_IP:8080"
FAILED=0

log() { echo "[natlab] $*"; }
trap 'echo "[natlab] ОШИБКА: команда упала (строка $LINENO): $BASH_COMMAND" >&2' ERR

cleanup() {
  pkill -f "$BIN/zpt" 2>/dev/null || true
  sleep 0.5
  for ns in zhostA zhostB znatA znatB zwan; do
    ip netns del "$ns" 2>/dev/null || true
  done
}

# nat_router NS WAN_IP LAN_NET HOST_NS HOST_IP MODE
nat_router() {
  local ns=$1 wanip=$2 lan=$3 host=$4 hostip=$5 mode=$6
  ip netns add "$ns"
  ip netns add "$host"
  # WAN: veth into the zwan bridge.
  ip link add "$ns-w" type veth peer name "br-$ns"
  ip link set "$ns-w" netns "$ns"
  ip link set "br-$ns" netns zwan
  ip -n zwan link set "br-$ns" master br0 up
  ip -n "$ns" addr add "$wanip/24" dev "$ns-w"
  ip -n "$ns" link set "$ns-w" up
  ip -n "$ns" link set lo up
  # LAN: veth to the host.
  ip link add "$ns-l" type veth peer name eth0 netns "$host"
  ip link set "$ns-l" netns "$ns"
  ip -n "$ns" addr add "$lan.1/24" dev "$ns-l"
  ip -n "$ns" link set "$ns-l" up
  ip -n "$host" addr add "$hostip/24" dev eth0
  ip -n "$host" link set eth0 up
  ip -n "$host" link set lo up
  ip -n "$host" route add default via "$lan.1"
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  local flags="" udp_rule=""
  [ "$mode" = symmetric ] && flags="fully-random"
  [ "$mode" = udp-blocked ] && udp_rule="iifname \"$ns-l\" meta l4proto udp drop"
  ip netns exec "$ns" nft -f - <<EOF
table ip nat {
  chain postrouting_nat {
    type nat hook postrouting priority 100;
    oifname "$ns-w" masquerade $flags
  }
}
table ip filter {
  chain forward_filter {
    type filter hook forward priority 0; policy drop;
    $udp_rule
    iifname "$ns-l" accept
    ct state established,related accept
  }
  # Like home routers: unsolicited packets from the internet to the router
  # itself are dropped. Otherwise Linux keeps a conntrack entry for them and
  # masquerade must pick another source port, which breaks hole punching.
  chain input_filter {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "$ns-l" accept
    ct state established,related accept
  }
}
EOF
}

setup() {
  local modeA=$1 modeB=$2
  cleanup
  rm -rf "$WORK" && mkdir -p "$WORK"
  ip netns add zwan
  ip -n zwan link add br0 type bridge
  ip -n zwan addr add "$CTRL_IP/24" dev br0
  ip -n zwan link set br0 up
  ip -n zwan link set lo up
  nat_router znatA 198.51.100.2 10.0.1 zhostA 10.0.1.2 "$modeA"
  nat_router znatB 198.51.100.3 10.0.2 zhostB 10.0.2.2 "$modeB"
}

start_controller() {
  "$BIN/zpt-controller" useradd -db "$WORK/c.db" -login admin -admin >/dev/null
  # The "real website" REALITY imitates: a TLS 1.3 server for lab.example.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=lab.example \
    -addext subjectAltName=DNS:lab.example -keyout "$WORK/site.key" -out "$WORK/site.crt" 2>/dev/null
  ip netns exec zwan openssl s_server -quiet -accept "$CTRL_IP:9443" -tls1_3 -www \
    -cert "$WORK/site.crt" -key "$WORK/site.key" >"$WORK/site.log" 2>&1 &
  ip netns exec zwan "$BIN/zpt-controller" serve -db "$WORK/c.db" -listen "$CTRL_IP:8080" -url "$CTRL_URL" \
    -stun "$CTRL_IP:3478,$CTRL_IP:3479" -relay "$CTRL_IP:3480" \
    -vless "$CTRL_IP:443" -vless-dest "$CTRL_IP:9443" -vless-sni lab.example \
    -log-level debug >"$WORK/controller.log" 2>&1 &
  for _ in $(seq 1 50); do
    ip netns exec zwan curl -fsS "$CTRL_URL/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  log "контроллер не запустился"; cat "$WORK/controller.log"; return 1
}

# start_node HOST_NS NAME INVITE
start_node() {
  local ns=$1 name=$2 inv=$3
  cat >"$WORK/$name.yaml" <<EOF
key_file: $WORK/$name/node.key
listen_port: 4790
portmap: false
log_level: debug
EOF
  ip netns exec "$ns" "$BIN/zpt" join -c "$WORK/$name.yaml" -name "$name" "$inv" >"$WORK/$name.join.log" 2>&1
  ip netns exec "$ns" "$BIN/zpt" up -c "$WORK/$name.yaml" >"$WORK/$name.log" 2>&1 &
}

# Both helpers may find nothing yet: that is not an error.
room_ip() { { ip -n "$1" -4 -o addr show dev zpt-lab 2>/dev/null || true; } | awk '{print $4}' | cut -d/ -f1; }

nat_seen() { { grep -o 'msg="external address checked".*nat=[a-z-]*' "$WORK/$1.log" || true; } | tail -1 | sed 's/.*nat=//'; }

# test_broadcast IP_A IP_B: LAN discovery through the room — a subnet
# broadcast and an mDNS-group multicast sent on A must arrive on B.
test_broadcast() {
  local ipA=$1 ipB=$2 bcast
  bcast="${ipB%.*}.255"
  ip netns exec zhostB python3 - "$WORK/bcast.out" "$ipB" <<'PY' &
import socket, struct, sys
out = open(sys.argv[1], "w")
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
b.bind(("0.0.0.0", 47000))
m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
m.bind(("224.0.0.251", 47001))
m.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
             struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(sys.argv[2])))
b.settimeout(15); m.settimeout(15)
for name, s in (("broadcast", b), ("multicast", m)):
    try:
        data, src = s.recvfrom(100)
        out.write(f"{name} {data.decode()} {src[0]}\n")
    except OSError as e:
        out.write(f"{name} none {e}\n")
    out.flush()
PY
  local rx=$!
  sleep 1
  ip netns exec zhostA python3 - "$ipA" "$bcast" <<'PY'
import socket, sys, time
me, bcast = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
m.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
for _ in range(5):
    s.sendto(b"lan-game", (bcast, 47000))
    m.sendto(b"mdns", ("224.0.0.251", 47001))
    time.sleep(0.5)
PY
  wait "$rx" || true
  log "LAN-обнаружение: $(tr '\n' ';' < "$WORK/bcast.out")"
  grep -q "^broadcast lan-game $ipA" "$WORK/bcast.out" || { log "ОШИБКА: broadcast не дошёл"; FAILED=1; }
  grep -q "^multicast mdns $ipA" "$WORK/bcast.out" || { log "ОШИБКА: multicast не дошёл"; FAILED=1; }
}

want_nat() { case $1 in cone) echo cone ;; symmetric) echo symmetric ;; udp-blocked) echo udp-blocked ;; esac; }

# path_seen NODE: how the node reaches its peer, from its log.
path_seen() {
  if grep -q 'msg="direct path found"' "$WORK/$1.log"; then echo direct
  elif grep -q 'msg="peer reachable through the relay"' "$WORK/$1.log"; then echo relay
  else echo none; fi
}

# run_case MODE_A MODE_B EXPECTED_PATH(direct|relay)
run_case() {
  local modeA=$1 modeB=$2 expect=$3
  log "=== NAT A: $modeA, NAT B: $modeB"
  CASE="$modeA-$modeB"
  setup "$modeA" "$modeB"
  start_controller
  local room inv
  room=$("$BIN/zpt-controller" room create -db "$WORK/c.db" -owner admin -name lab -policy auto | awk '/room id/{print $3}')
  inv=$("$BIN/zpt-controller" invite create -db "$WORK/c.db" -room "$room" -url "$CTRL_URL" -uses 2 -auto)
  start_node zhostA a "$inv"
  start_node zhostB b "$inv"

  local ipA="" ipB=""
  for _ in $(seq 1 60); do
    ipA=$(room_ip zhostA); ipB=$(room_ip zhostB)
    [ -n "$ipA" ] && [ -n "$ipB" ] && break
    sleep 0.5
  done
  if [ -z "$ipA" ] || [ -z "$ipB" ]; then
    log "ОШИБКА: интерфейс комнаты не поднялся (A=$ipA B=$ipB)"; FAILED=1; dump; return
  fi
  log "интерфейсы подняты: A=$ipA B=$ipB"

  local ok=no start=$SECONDS
  for _ in $(seq 1 40); do
    if ip netns exec zhostA ping -c1 -W1 "$ipB" >/dev/null 2>&1; then ok=yes; break; fi
  done
  local natA natB
  natA=$(nat_seen a); natB=$(nat_seen b)
  log "тип NAT: A=$natA (ожидался $(want_nat "$modeA")), B=$natB (ожидался $(want_nat "$modeB"))"
  local path
  path=$(path_seen a)
  # The relay often answers before NAT holes are punched; a direct path
  # must replace it shortly.
  if [ "$ok" = yes ] && [ "$expect" = direct ]; then
    for _ in $(seq 1 30); do
      path=$(path_seen a)
      [ "$path" = direct ] && break
      sleep 1
    done
  fi
  log "связь: $ok за $((SECONDS - start)) с, путь: $path (ожидался $expect)"

  local want_nat_a want_nat_b
  want_nat_a=$(want_nat "$modeA")
  want_nat_b=$(want_nat "$modeB")
  if [ "$natA" != "$want_nat_a" ] || [ "$natB" != "$want_nat_b" ]; then
    log "ОШИБКА: тип NAT определён неверно"; FAILED=1; dump
  fi
  if [ "$ok" != yes ]; then
    log "ОШИБКА: нет связи"; FAILED=1; dump
  elif [ "$path" != "$expect" ]; then
    log "ОШИБКА: трафик идёт не тем путём"; FAILED=1; dump
  fi
  if [ "$ok" = yes ] && [ "$CASE" = cone-cone ]; then
    test_broadcast "$ipA" "$ipB"
  fi
  if [ "$ok" = yes ]; then
    # Real traffic over the tunnel in both directions.
    ip netns exec zhostB ping -c3 -W2 "$ipA" >/dev/null || { log "ОШИБКА: обратное направление"; FAILED=1; }
  fi
}

CASE=""
dump() {
  local dir="$WORK/../natlab-logs/$CASE"
  mkdir -p "$dir"
  cp "$WORK"/*.log "$dir/" 2>/dev/null || true
  for f in "$WORK"/a.log "$WORK"/b.log; do
    log "--- хвост $f"; tail -n 30 "$f" || true
  done
}

trap cleanup EXIT
run_case cone cone direct
run_case cone symmetric relay
run_case symmetric symmetric relay
run_case udp-blocked cone relay
if ! grep -q "relay reached through VLESS" "$WORK/a.log"; then
  log "ОШИБКА: при закрытом UDP узел A не дошёл до relay через VLESS"; FAILED=1; CASE=udp-blocked-cone; dump
else
  log "узел A за закрытым UDP дошёл до relay через VLESS + REALITY"
fi
if [ "$FAILED" != 0 ]; then
  log "НЕ ПРОЙДЕНО"; exit 1
fi
log "ПРОЙДЕНО"
