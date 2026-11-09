#!/bin/bash
# Starts three local Samba servers for SMB3Tests, using Homebrew's Samba
# (`brew install samba`), as the current user, without root:
#   4446  SMB 3.1.1 only, encryption required        (SMB3_TEST_PORT)
#   4447  SMB 3.0 and up, encryption and signing required (SMB3_LEGACY_TEST_PORT)
#   4448  SMB 2.0.2 and up, signing required, encryption offered but not required (SMB3_SIGNING_TEST_PORT)
# Each has a share "Encrypted". The account is the current user with the
# password "testpass", so run the tests as:
#   SMB3_TEST_USER=$(id -un) SMB3_TEST_PASSWORD=testpass swift test --filter SMB3
# `Scripts/smb3-test-server.sh stop` stops them.
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="$PWD/.samba-test"   # Samba's socket paths must stay short
PREFIX="$(brew --prefix samba)"
SMBD="$PREFIX/sbin/samba-dot-org-smbd"
[ -x "$SMBD" ] || SMBD="$PREFIX/sbin/smbd"

stop() {
  for pidfile in "$BASE"/*/pid/*.pid; do
    [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
  done
}

if [ "${1:-}" = "stop" ]; then stop; exit 0; fi
stop
sleep 1

mkdir -p "$BASE/share"
printf 'hello\n' > "$BASE/share/hello.txt"

start() { # name port extra-global-lines
  local dir="$BASE/$1"
  rm -rf "$dir"; mkdir -p "$dir"/{private,lock,state,cache,pid,ncalrpc}
  cat > "$dir/smb.conf" <<CONF
[global]
  server role = standalone server
  smb ports = $2
  bind interfaces only = yes
  interfaces = 127.0.0.1
  private dir = $dir/private
  lock directory = $dir/lock
  state directory = $dir/state
  cache directory = $dir/cache
  pid directory = $dir/pid
  ncalrpc dir = $dir/ncalrpc
  log file = $dir/log.%m
  passdb backend = tdbsam:$dir/private/passdb.tdb
  load printers = no
  disable spoolss = yes
  map to guest = never
$3
[Encrypted]
  path = $BASE/share
  read only = no
  valid users = $(id -un)
  # Without these, Samba on macOS makes folders with no permissions at all
  # (d---------: it maps an empty NT ACL or DOS attributes onto the mode),
  # so nothing can go in them or remove them.
  force create mode = 0644
  force directory mode = 0755
  nt acl support = no
  store dos attributes = no
  ea support = no
  map archive = no
CONF
  printf 'testpass\ntestpass\n' | "$PREFIX/bin/pdbedit" -s "$dir/smb.conf" -a -u "$(id -un)" -t >/dev/null 2>&1
  nohup "$SMBD" -s "$dir/smb.conf" -F --debug-stdout -d 1 > "$dir/smbd.out" 2>&1 &
}

start smb3 4446 "  server min protocol = SMB3_11
  server smb encrypt = required"
start legacy 4447 "  server min protocol = SMB3_00
  server smb encrypt = required
  server signing = mandatory"
start signing 4448 "  server min protocol = SMB2_02
  server smb encrypt = if_required
  server signing = mandatory"

for port in 4446 4447 4448; do
  for _ in $(seq 20); do nc -z 127.0.0.1 $port 2>/dev/null && break; sleep 0.5; done
  nc -z 127.0.0.1 $port 2>/dev/null && echo "port $port up" || { echo "port $port did not start"; exit 1; }
done
