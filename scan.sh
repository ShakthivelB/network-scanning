#!/bin/bash
# ============================================================
#  scan.sh — Full Network Assessment Automation
#  Runs netscan.py then generates HTML report automatically
#
#  Usage:
#    chmod +x scan.sh
#    ./scan.sh 192.168.56.101
# ============================================================

# ── Colors ──────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
CYAN="\033[36m"
BRIGHT_CYAN="\033[96m"
BRIGHT_GREEN="\033[92m"
BRIGHT_WHITE="\033[97m"
RED="\033[31m"
YELLOW="\033[33m"

cprint() { echo -e "${1}${2}${RESET}"; }

# ── Banner ───────────────────────────────────────────────────
print_banner() {
  echo ""
  cprint "$BOLD$CYAN" "=================================================="
  cprint "$BOLD$BRIGHT_CYAN" "  INAVRF // Automated Network Assessment"
  cprint "$BOLD$CYAN" "=================================================="
  cprint "$BOLD$BRIGHT_WHITE" "  Target : $TARGET"
  cprint "$BOLD$CYAN" "=================================================="
  echo ""
}

# ── Usage ────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage:${RESET}  ./scan.sh <target-ip>"
  echo -e "${BOLD}Example:${RESET} ./scan.sh 192.168.56.101"
  exit 1
}

# ── Check target argument ────────────────────────────────────
if [[ -z "$1" ]]; then
  cprint "$RED" "[ERROR] No target IP provided."
  usage
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETSCAN="$SCRIPT_DIR/net.py"
REPORT="$SCRIPT_DIR/report.py"

# ── Validate required files ──────────────────────────────────
if [[ ! -f "$NETSCAN" ]]; then
  cprint "$RED" "[ERROR] net.py not found at: $NETSCAN"
  exit 1
fi

if [[ ! -f "$REPORT" ]]; then
  cprint "$RED" "[ERROR] report.py not found at: $REPORT"
  exit 1
fi

# ── Check python3 ────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  cprint "$RED" "[ERROR] python3 not found on PATH."
  exit 1
fi

print_banner

# ── Step 1: Run nwt.py ───────────────────────────────────
cprint "$BOLD$BRIGHT_CYAN" "  [1/3] Running network scans ..."
echo ""

python3 "$NETSCAN" -t "$TARGET"
SCAN_EXIT=$?

if [[ $SCAN_EXIT -ne 0 ]]; then
  cprint "$YELLOW" "\n  [!] net.py exited with code $SCAN_EXIT (some scans may have failed)."
  cprint "$YELLOW" "      Continuing to report generation ..."
fi

# ── Step 2: Find the latest scan folder ─────────────────────
echo ""
cprint "$BOLD$BRIGHT_CYAN" "  [2/3] Locating latest scan folder ..."

LATEST_SCAN=$(ls -td "$SCRIPT_DIR/scans"/*/  2>/dev/null | head -1)

if [[ -z "$LATEST_SCAN" ]]; then
  cprint "$RED" "[ERROR] No scan folder found under $SCRIPT_DIR/scans/"
  exit 1
fi

# Strip trailing slash for display
LATEST_SCAN="${LATEST_SCAN%/}"
cprint "$BRIGHT_GREEN" "  [✓] Scan folder: $LATEST_SCAN"

# ── Fix permissions (nmap/sudo may have made files root-owned) ──
cprint "$BRIGHT_CYAN" "  [*] Fixing scan folder permissions ..."
sudo chown -R "$USER":"$USER" "$SCRIPT_DIR/scans/" 2>/dev/null

# ── Step 3: Generate HTML report ────────────────────────────
echo ""
cprint "$BOLD$BRIGHT_CYAN" "  [3/3] Generating HTML report ..."
echo ""

python3 "$REPORT" -d "$LATEST_SCAN"
REPORT_EXIT=$?

if [[ $REPORT_EXIT -ne 0 ]]; then
  cprint "$RED" "\n  [✗] Report generation failed (exit code $REPORT_EXIT)."
  exit 1
fi

# ── Done ─────────────────────────────────────────────────────
REPORT_FILE="$LATEST_SCAN/report.html"

echo ""
cprint "$BOLD$CYAN" "=================================================="
cprint "$BOLD$BRIGHT_GREEN" "  All done!"
cprint "$BOLD$BRIGHT_WHITE" "  Scan data : $LATEST_SCAN"
cprint "$BOLD$BRIGHT_WHITE" "  Report    : $REPORT_FILE"
cprint "$BOLD$CYAN" "=================================================="
echo ""

# Auto-open the report in the browser
if command -v xdg-open &>/dev/null; then
  cprint "$BRIGHT_CYAN" "  [*] Opening report in browser ..."
  xdg-open "$REPORT_FILE" 2>/dev/null &
fi
