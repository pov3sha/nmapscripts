#!/usr/bin/env bash
# Runs the reference script and both enhanced scripts against the SAME localhost
# targets and saves the real Nmap output to outputs/*.txt.
# Run from the project root:  bash tests/run_blog_tests.sh
# Targets are 127.0.0.1 only. Only the one named script runs each time.
set -u

OUTDIR=outputs
mkdir -p "$OUTDIR"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

start_server() { python3 tests/lab_server.py "$1" "$2" & PIDS+=($!); }

# Lab services on localhost:
#   2222 sends "SSH-2.0-LabServer_1.0 lab-test"
#   2224 sends "220 lab.example ESMTP ready"
#   2225 accepts the connection and sends nothing
start_server ssh 2222
start_server text 2224
start_server silent 2225
sleep 1

# Port 22 is the real SSH server (start it with: sudo systemctl start ssh).
PORTS=22,2222,2224,2225

for pair in "banner:banner.timeout" "banner-parsed:banner-parsed.timeout" "banner-timing:banner-timing.timeout"; do
  script="${pair%%:*}"
  arg="${pair##*:}"
  file="$OUTDIR/$script.txt"
  {
    echo "\$ nmap -Pn -n -p $PORTS --script $script --script-args $arg=2 127.0.0.1"
    nmap -Pn -n -p "$PORTS" --script "$script" --script-args "$arg=2" 127.0.0.1 2>&1
  } | tee "$file"
  echo
done

{
  nmap --version | head -2
  uname -srm
  [ -r /etc/os-release ] && grep PRETTY_NAME /etc/os-release
} > "$OUTDIR/environment.txt"
echo "Saved outputs to $OUTDIR/"
