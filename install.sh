#!/usr/bin/env bash
# =============================================================================
# WebWeaver — Automated installer for Kali Linux
# Usage: sudo bash install.sh
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
PURPLE='\033[1;38;5;99m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
DIM='\033[2m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  [+]${NC} $*"; }
info() { echo -e "${CYAN}  [*]${NC} $*"; }
warn() { echo -e "${YELLOW}  [!]${NC} $*"; }
die()  { echo -e "${RED}  [x]${NC} $*" >&2; exit 1; }
step() { echo -e "\n${PURPLE}───────────────────────────────────────────────${NC}"; \
         echo -e "${PURPLE}  $*${NC}"; \
         echo -e "${PURPLE}───────────────────────────────────────────────${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${PURPLE}"
cat << 'BANNER'

 _       __     __  _       __
| |     / /__  / /_| |     / /__  ____ __   _____  _____
| | /| / / _ \/ __ \ | /| / / _ \/ __ `/ | / / _ \/ ___/
| |/ |/ /  __/ /_/ / |/ |/ /  __/ /_/ /| |/ /  __/ /
|__/|__/\___/_.___/|__/|__/\___/\__,_/ |___/\___/_/

     Web2 bug-bounty capture & analysis toolkit — Kali Linux
                         installer v1.0

BANNER
echo -e "${NC}"

# ── Sanity checks ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must be run as root.  Usage: sudo bash install.sh"

# Determine the real (non-root) user who invoked sudo.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    REAL_USER="$SUDO_USER"
else
    # Fallback: ask if someone runs as root directly with no SUDO_USER.
    warn "Could not detect the invoking user via SUDO_USER."
    read -rp "  Enter the username to install Rust/build under: " REAL_USER
    [[ -n "$REAL_USER" ]] || die "No username provided."
fi

REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6) \
    || die "Cannot find home directory for user '$REAL_USER'."
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CARGO_ENV="$REAL_HOME/.cargo/env"
CARGO_BIN="$REAL_HOME/.cargo/bin/cargo"

info "Installing for user : ${YELLOW}$REAL_USER${NC}"
info "Home directory      : ${YELLOW}$REAL_HOME${NC}"
info "Source directory    : ${YELLOW}$INSTALL_DIR${NC}"

# ── Step 1: System packages ───────────────────────────────────────────────────
step "Step 1/6 — System packages"

info "Updating apt package lists..."
apt-get update -qq

PACKAGES=(curl build-essential pkg-config libssl-dev ca-certificates python3-pip)
MISSING=()
for pkg in "${PACKAGES[@]}"; do
    dpkg -s "$pkg" &>/dev/null || MISSING+=("$pkg")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Installing: ${MISSING[*]}"
    apt-get install -y -qq "${MISSING[@]}"
fi
ok "System packages ready."

# ── Step 2: mitmproxy ─────────────────────────────────────────────────────────
step "Step 2/6 — mitmproxy"

if command -v mitmproxy &>/dev/null; then
    ok "mitmproxy already installed: $(mitmproxy --version 2>&1 | head -1)"
else
    info "Installing mitmproxy via apt..."
    if apt-get install -y -qq mitmproxy 2>/dev/null; then
        ok "mitmproxy installed via apt: $(mitmproxy --version 2>&1 | head -1)"
    else
        warn "apt install failed — trying pip3..."
        pip3 install --quiet mitmproxy
        # Ensure pip-installed binaries are on PATH for this session.
        export PATH="$PATH:/usr/local/bin"
        ok "mitmproxy installed via pip3: $(mitmproxy --version 2>&1 | head -1)"
    fi
fi

# ── Step 3: Rust toolchain ────────────────────────────────────────────────────
step "Step 3/6 — Rust toolchain"

if sudo -u "$REAL_USER" HOME="$REAL_HOME" bash -c \
    "[[ -x '$REAL_HOME/.cargo/bin/cargo' ]]" 2>/dev/null; then
    RUST_VER=$(sudo -u "$REAL_USER" HOME="$REAL_HOME" \
        "$REAL_HOME/.cargo/bin/rustc" --version 2>/dev/null || echo "unknown")
    ok "Rust already installed: $RUST_VER"
else
    info "Installing Rust toolchain via rustup (this takes ~30 seconds)..."
    sudo -u "$REAL_USER" HOME="$REAL_HOME" bash -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --no-modify-path --quiet' \
        || die "rustup installation failed."
    RUST_VER=$(sudo -u "$REAL_USER" HOME="$REAL_HOME" \
        "$REAL_HOME/.cargo/bin/rustc" --version 2>/dev/null || echo "installed")
    ok "Rust installed: $RUST_VER"
fi

[[ -f "$CARGO_ENV" ]] || die "Cargo env file not found at $CARGO_ENV"

# ── Step 4: Build release binary ─────────────────────────────────────────────
step "Step 4/6 — Build WebWeaver (cargo build --release)"

info "This takes ~2 minutes on first build (compiling all dependencies)..."
sudo -u "$REAL_USER" HOME="$REAL_HOME" bash -c \
    "source '$CARGO_ENV' && cd '$INSTALL_DIR' && cargo build --release" \
    || die "Cargo build failed. Check the output above for errors."

BINARY="$INSTALL_DIR/target/release/lw"
[[ -f "$BINARY" ]] || die "Build succeeded but binary not found at $BINARY"
ok "Binary built: $(du -h "$BINARY" | cut -f1) — $BINARY"

# ── Step 5: Install binary ────────────────────────────────────────────────────
step "Step 5/6 — Install lw to /usr/local/bin"

cp "$BINARY" /usr/local/bin/lw
chmod 755 /usr/local/bin/lw
chown root:root /usr/local/bin/lw

# Install the mitmproxy addon to a fixed system path so `lw target` can
# find it without needing to run from the source directory.
ADDON_DEST_DIR="/usr/local/share/webweaver"
mkdir -p "$ADDON_DEST_DIR"
cp "$INSTALL_DIR/lw-proxy/addon.py" "$ADDON_DEST_DIR/addon.py"
chmod 644 "$ADDON_DEST_DIR/addon.py"
ok "Addon installed: $ADDON_DEST_DIR/addon.py"

ok "Installed: $(command -v lw)"
info "Version check:"
lw --version 2>&1 | sed 's/^/           /'

# ── Step 6: mitmproxy CA certificate ─────────────────────────────────────────
step "Step 6/6 — mitmproxy CA certificate"

MITM_DIR="$REAL_HOME/.mitmproxy"
CA_PEM="$MITM_DIR/mitmproxy-ca-cert.pem"
CA_DEST="/usr/local/share/ca-certificates/mitmproxy.crt"

if [[ ! -f "$CA_PEM" ]]; then
    info "Generating mitmproxy CA certificate (running mitmdump briefly)..."
    # Run mitmdump for a few seconds — enough for it to create the CA on first
    # launch — then kill it cleanly.  The exit code from timeout is suppressed.
    sudo -u "$REAL_USER" HOME="$REAL_HOME" \
        timeout 6 mitmdump --no-web-open-browser 2>/dev/null || true
    sleep 1
fi

if [[ -f "$CA_PEM" ]]; then
    cp "$CA_PEM" "$CA_DEST"
    update-ca-certificates --fresh -v 2>&1 | grep -E "(mitmproxy|Added)" | \
        sed 's/^/           /' || true
    ok "mitmproxy CA trusted system-wide: $CA_DEST"

    # ── Firefox / Chromium NSS databases ─────────────────────────────────────
    if command -v certutil &>/dev/null; then
        info "Adding CA to browser NSS databases..."
        while IFS= read -r -d '' db_file; do
            db_dir="$(dirname "$db_file")"
            sudo -u "$REAL_USER" certutil \
                -A -n "mitmproxy" -t "TCu,Cu,Tu" \
                -i "$CA_PEM" -d "sql:$db_dir" 2>/dev/null \
                && info "  Added to: $db_dir" || true
        done < <(find "$REAL_HOME" \
            \( -name "cert9.db" -o -name "cert8.db" \) \
            -print0 2>/dev/null)
        ok "Browser NSS databases updated."
    else
        warn "certutil not found — skipping browser NSS update."
        warn "To trust in Firefox: Preferences → Privacy & Security → Certificates"
        warn "  → View Certificates → Authorities → Import → $CA_PEM"
    fi
else
    warn "Could not find mitmproxy CA at $CA_PEM"
    warn "Run 'mitmdump' once as $REAL_USER to generate it, then:"
    warn "  sudo cp $CA_PEM $CA_DEST && sudo update-ca-certificates"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  WebWeaver installation complete!${NC}"
echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Binary     ${NC}  $(command -v lw 2>/dev/null || echo '/usr/local/bin/lw')"
echo -e "  ${CYAN}Proxy addon${NC}  $ADDON_DEST_DIR/addon.py"
echo -e "  ${CYAN}mitmproxy  ${NC}  $(command -v mitmproxy)"
echo -e "  ${CYAN}CA cert    ${NC}  $CA_DEST"
echo ""
echo -e "${YELLOW}  Quick start — one command does everything:${NC}"
echo ""
echo -e "    lw target https://app.example.com"
echo ""
echo -e "${DIM}    # The wizard will:${NC}"
echo -e "${DIM}    #  1. Start the proxy and guide you through browsing as admin${NC}"
echo -e "${DIM}    #  2. Switch sessions and guide you through browsing as guest${NC}"
echo -e "${DIM}    #  3. Run IDOR, race-condition, and sequence-break scans${NC}"
echo -e "${DIM}    #  4. Let you review findings and generate a report${NC}"
echo ""
echo -e "${YELLOW}  Options:${NC}"
echo -e "    lw target https://app.example.com --format hackerone --output h1-report.md"
echo -e "    lw target https://app.example.com --port 8888 --no-confirm"
echo ""
echo -e "  See ${CYAN}README.md${NC} for the full workflow."
echo ""
