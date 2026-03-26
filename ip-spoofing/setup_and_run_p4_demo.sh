#!/usr/bin/env bash
set -euo pipefail

# One-command setup + compile + test runner for the IP spoofing P4 project.
# It compiles BOTH P4 programs:
#   1) ip-spoofing-defense.p4 (enhanced)
#   2) ip-source-guard.p4 (basic)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() {
  printf "\n[%s] %s\n" "INFO" "$1"
}

warn() {
  printf "\n[%s] %s\n" "WARN" "$1"
}

err() {
  printf "\n[%s] %s\n" "ERROR" "$1" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

docker_usable() {
  if ! need_cmd docker; then
    return 1
  fi
  docker info >/dev/null 2>&1
}

can_sudo() {
  sudo -n true >/dev/null 2>&1
}

install_with_apt_if_possible() {
  local missing=()

  need_cmd p4c || missing+=("p4c")
  need_cmd simple_switch || missing+=("simple_switch")
  need_cmd simple_switch_CLI || missing+=("simple_switch_CLI")
  need_cmd mn || missing+=("mn")

  if [[ ${#missing[@]} -eq 0 ]]; then
    log "All key tools already installed: p4c, simple_switch, simple_switch_CLI, mn"
    return 0
  fi

  warn "Missing tools detected: ${missing[*]}"

  if ! can_sudo; then
    warn "Passwordless sudo is not available in this shell, so auto-install is skipped."
    warn "Run this script manually with sudo to allow dependency installation:"
    warn "  sudo bash setup_and_run_p4_demo.sh"
    return 0
  fi

  log "Updating apt package index"
  sudo apt-get update

  # Core Python/test dependencies
  log "Installing base dependencies (python/mininet/scapy/tcpdump)"
  sudo apt-get install -y python3 python3-pip python3-scapy mininet tcpdump

  # Try common package names used across distributions.
  # Attempt 1: p4lang package names
  if ! need_cmd p4c || ! need_cmd simple_switch || ! need_cmd simple_switch_CLI; then
    log "Trying to install P4 toolchain via p4lang package names"
    sudo apt-get install -y p4lang-p4c p4lang-bmv2 || true
  fi

  # Attempt 2: generic package names
  if ! need_cmd p4c || ! need_cmd simple_switch || ! need_cmd simple_switch_CLI; then
    log "Trying to install P4 toolchain via generic package names"
    sudo apt-get install -y p4c bmv2 || true
  fi

  # Optional: ensure scapy is available even if distro package lags
  if ! python3 -c "import scapy" >/dev/null 2>&1; then
    log "Installing Scapy via pip"
    python3 -m pip install --user scapy
  fi

  # Final tool status
  log "Tool status after install attempts"
  for t in p4c simple_switch simple_switch_CLI mn; do
    if need_cmd "$t"; then
      printf "  - %-18s OK (%s)\n" "$t" "$(command -v "$t")"
    else
      printf "  - %-18s MISSING\n" "$t"
    fi
  done

  if docker_usable; then
    printf "  - %-18s OK\n" "docker-daemon"
  else
    printf "  - %-18s MISSING/NO-ACCESS\n" "docker-daemon"
  fi
}

compile_with_local_p4c() {
  log "Compiling with local p4c"

  p4c --target bmv2 --arch v1model \
    -o build/ip-spoofing-defense.json \
    ip-spoofing-defense.p4

  p4c --target bmv2 --arch v1model \
    --p4runtime-files build/ip-spoofing-defense.p4info.txt \
    ip-spoofing-defense.p4

  p4c --target bmv2 --arch v1model \
    -o build/ip-source-guard.json \
    ip-source-guard.p4

  p4c --target bmv2 --arch v1model \
    --p4runtime-files build/ip-source-guard.p4info.txt \
    ip-source-guard.p4
}

compile_with_docker_p4c() {
  local image="p4lang/p4c"
  log "Compiling with Dockerized p4c image: ${image}"

  docker pull "${image}"

  # The current p4lang/p4c image may miss libboost_iostreams at runtime for
  # p4c-bm2-ss backend. Install it inside the ephemeral container first.
  docker run --rm -v "$SCRIPT_DIR":/work -w /work --entrypoint bash "${image}" -lc '
    set -euo pipefail
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-iostreams1.71.0 >/dev/null
    p4c --target bmv2 --arch v1model -o build/ip-spoofing-defense.json ip-spoofing-defense.p4
    p4c --target bmv2 --arch v1model --p4runtime-files build/ip-spoofing-defense.p4info.txt ip-spoofing-defense.p4
    p4c --target bmv2 --arch v1model -o build/ip-source-guard.json ip-source-guard.p4
    p4c --target bmv2 --arch v1model --p4runtime-files build/ip-source-guard.p4info.txt ip-source-guard.p4
  '
}

compile_p4_programs() {

  mkdir -p build

  log "Compiling enhanced program: ip-spoofing-defense.p4"
  log "Compiling basic program: ip-source-guard.p4"

  if need_cmd p4c; then
    compile_with_local_p4c
  elif docker_usable; then
    warn "Local p4c not found. Falling back to Docker-based compilation."
    compile_with_docker_p4c
  else
    err "Neither local p4c nor usable Docker daemon is available."
    err "Install p4c or run with sudo and ensure Docker daemon is running."
    exit 1
  fi

  log "Compilation complete. Generated artifacts:"
  ls -1 build | sed 's/^/  - /'
}

run_tests() {
  log "Running behavioral + simulation test suite"
  python3 run_all_tests.py

  if [[ $EUID -eq 0 ]]; then
    log "Running Mininet integration test as root"
    printf 'n\n' | python3 mininet_p4_test.py || true
  else
    warn "Skipping Mininet integration in this run (root required)."
    warn "Run this command for Mininet validation:"
    warn "  sudo python3 mininet_p4_test.py"
  fi
}

print_bmv2_usage() {
  if need_cmd simple_switch; then
    cat <<'EOF'

[INFO] BMv2 run example (enhanced P4 program)
  sudo simple_switch \
    -i 0@veth0 -i 1@veth2 \
    --log-console --log-level debug \
    build/ip-spoofing-defense.json

  simple_switch_CLI < s1-runtime-new.json
EOF
  fi
}

main() {
  log "Starting one-command setup + compile + run"
  install_with_apt_if_possible
  compile_p4_programs
  run_tests
  print_bmv2_usage
  log "Done"
}

main "$@"
