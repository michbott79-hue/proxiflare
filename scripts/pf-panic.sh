#!/bin/bash
# pf-panic — ripristino rete di emergenza se proxiflare rompe tutto
# Uso: sudo pf-panic
# Rimuove TUTTE le tracce di routing proxiflare senza toccare nft di Docker/libvirt

set +e

echo "[pf-panic] killing daemon..."
systemctl stop proxiflare-daemon 2>/dev/null
pkill -9 -f proxiflare-daemon

echo "[pf-panic] removing nftables proxiflare table..."
nft delete table inet proxiflare 2>/dev/null
nft delete table ip proxiflare 2>/dev/null

echo "[pf-panic] removing ip rule fwmark..."
# rimuove tutte le regole con fwmark 0x1 (marker proxiflare)
while ip rule show | grep -q "fwmark 0x1"; do
  ip rule del fwmark 0x1 lookup 100 2>/dev/null || break
done

echo "[pf-panic] flushing table 100..."
ip route flush table 100 2>/dev/null

echo "[pf-panic] emptying cgroup..."
if [ -d /sys/fs/cgroup/proxiflare.slice ]; then
  # sposta eventuali PID residui nel cgroup root
  if [ -f /sys/fs/cgroup/proxiflare.slice/cgroup.procs ]; then
    while read pid; do
      [ -n "$pid" ] && echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null
    done < /sys/fs/cgroup/proxiflare.slice/cgroup.procs
  fi
  rmdir /sys/fs/cgroup/proxiflare.slice 2>/dev/null
fi

echo "[pf-panic] done. Test: curl -sI https://1.1.1.1"
