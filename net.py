#!/usr/bin/env python3
"""
netscan.py - Automated Network Assessment CLI Tool
Runs a suite of network scanners against an authorized target.
"""

import argparse
import datetime
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# ANSI COLOR CODES
# ---------------------------------------------------------------------------

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    CYAN    = "\033[36m"
    MAGENTA = "\033[35m"
    WHITE   = "\033[37m"
    BRIGHT_GREEN  = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN   = "\033[96m"
    BRIGHT_WHITE  = "\033[97m"


def cprint(msg: str, color: str = Colors.RESET, bold: bool = False) -> None:
    """Print a message with optional ANSI color and bold."""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{msg}{Colors.RESET}")


def print_banner(target: str) -> None:
    cprint("=" * 50, Colors.CYAN, bold=True)
    cprint("  INAVRF Network Scanner", Colors.BRIGHT_CYAN, bold=True)
    cprint("=" * 50, Colors.CYAN, bold=True)
    cprint(f"  Target : {target}", Colors.BRIGHT_WHITE, bold=True)
    cprint("=" * 50, Colors.CYAN, bold=True)
    print()


def print_footer(output_dir: pathlib.Path) -> None:
    print()
    cprint("=" * 50, Colors.CYAN, bold=True)
    cprint("  Finished", Colors.BRIGHT_GREEN, bold=True)
    cprint(f"  Outputs saved in: {output_dir}", Colors.BRIGHT_WHITE)
    cprint("=" * 50, Colors.CYAN, bold=True)


# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------

logger = logging.getLogger("netscan")


def setup_logging(log_path: pathlib.Path) -> None:
    """Configure file + stderr logging."""
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Stderr handler — only WARNING and above so we don't clutter the terminal
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)
    logger.addHandler(sh)


# ---------------------------------------------------------------------------
# TOOL VALIDATION
# ---------------------------------------------------------------------------

def check_tool(name: str) -> bool:
    """Return True if *name* is on PATH, False otherwise."""
    found = shutil.which(name) is not None
    if not found:
        cprint(f"  [SKIPPED] '{name}' not found on PATH.", Colors.YELLOW)
        logger.warning("Tool '%s' not found – skipping scanner.", name)
    return found


# ---------------------------------------------------------------------------
# OUTPUT DIRECTORY
# ---------------------------------------------------------------------------

def create_output_directory() -> pathlib.Path:
    """Create scans/<timestamp>/ and return the Path."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = pathlib.Path("scans") / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


# ---------------------------------------------------------------------------
# CORE COMMAND RUNNER
# ---------------------------------------------------------------------------

def run_command(
    cmd: list,
    output_file: pathlib.Path,
    label: str,
    file_written_by_tool: bool = False,
) -> bool:
    """
    Execute *cmd* (list, never shell=True), capture stdout+stderr,
    write both to *output_file*, measure elapsed time, and return True/False.

    If file_written_by_tool=True the tool writes its own output file (e.g.
    nmap -oX) so we do NOT overwrite it with stdout — we only save stderr
    alongside it for debugging.
    """
    cprint(f"\n  [{label}] Starting ...", Colors.BRIGHT_CYAN, bold=True)
    logger.info("START  [%s]  cmd=%s", label, " ".join(str(c) for c in cmd))
    t0 = time.monotonic()

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
        )
        elapsed = time.monotonic() - t0

        if file_written_by_tool:
            # Tool wrote its own file; only save stderr if something went wrong
            if result.stderr and result.returncode != 0:
                stderr_file = output_file.with_suffix(".stderr.txt")
                stderr_file.write_bytes(result.stderr)
        else:
            # Save stdout + stderr into the output file
            with output_file.open("wb") as fh:
                fh.write(result.stdout)
                if result.stderr:
                    fh.write(b"\n\n--- STDERR ---\n")
                    fh.write(result.stderr)

        if result.returncode == 0:
            cprint(f"  [\u2713] {label} completed in {elapsed:.1f}s  ->  {output_file.name}",
                   Colors.BRIGHT_GREEN)
            logger.info("OK     [%s]  duration=%.1fs  rc=0", label, elapsed)
            return True
        else:
            stderr_snippet = result.stderr.decode(errors="replace")[:300].strip()
            cprint(f"  [\u2717] {label} exited with code {result.returncode} in {elapsed:.1f}s",
                   Colors.YELLOW)
            if stderr_snippet:
                cprint(f"      stderr: {stderr_snippet}", Colors.YELLOW)
            logger.warning("FAIL   [%s]  duration=%.1fs  rc=%d  stderr=%s",
                           label, elapsed, result.returncode, stderr_snippet)
            return False

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        cprint(f"  [\u2717] {label} timed out after {elapsed:.0f}s.", Colors.RED)
        logger.error("TIMEOUT [%s]  duration=%.1fs", label, elapsed)
        if not output_file.exists():
            output_file.write_bytes(b"[TIMEOUT - no output captured]\n")
        return False

    except Exception as exc:
        elapsed = time.monotonic() - t0
        cprint(f"  [\u2717] {label} raised an exception: {exc}", Colors.RED)
        logger.error("ERROR  [%s]  duration=%.1fs  exc=%s", label, elapsed, exc)
        if not output_file.exists():
            output_file.write_bytes(f"[EXCEPTION: {exc}]\n".encode())
        return False


# ---------------------------------------------------------------------------
# INDIVIDUAL SCANNERS
# ---------------------------------------------------------------------------

def host_discovery(target: str, out_dir: pathlib.Path) -> bool:
    """nmap -sn  (ping sweep / host discovery)."""
    if not check_tool("nmap"):
        return False
    cmd = ["nmap", "-sn", "-oX", str(out_dir / "host_discovery.xml"), target]
    return run_command(cmd, out_dir / "host_discovery.xml", "Host Discovery", file_written_by_tool=True)


def port_scan(target: str, out_dir: pathlib.Path) -> bool:
    """nmap -p-  (full TCP port scan)."""
    if not check_tool("nmap"):
        return False
    cmd = ["nmap", "-p-", "-oX", str(out_dir / "ports.xml"), target]
    return run_command(cmd, out_dir / "ports.xml", "Full Port Scan", file_written_by_tool=True)


def service_scan(target: str, out_dir: pathlib.Path) -> bool:
    """nmap -sV  (version/service detection)."""
    if not check_tool("nmap"):
        return False
    cmd = ["nmap", "-sV", "-oX", str(out_dir / "services.xml"), target]
    return run_command(cmd, out_dir / "services.xml", "Service Detection", file_written_by_tool=True)


def os_detection(target: str, out_dir: pathlib.Path) -> bool:
    """sudo nmap -O  (OS fingerprinting)."""
    if not check_tool("nmap"):
        return False
    cmd = ["sudo", "nmap", "-O", "-oX", str(out_dir / "os.xml"), target]
    return run_command(cmd, out_dir / "os.xml", "OS Detection", file_written_by_tool=True)


def nse_scan(target: str, out_dir: pathlib.Path) -> bool:
    """sudo nmap -sC  (default NSE scripts)."""
    if not check_tool("nmap"):
        return False
    cmd = ["sudo", "nmap", "-sC", "-oX", str(out_dir / "scripts.xml"), target]
    return run_command(cmd, out_dir / "scripts.xml", "NSE Scripts", file_written_by_tool=True)


def whatweb_scan(target: str, out_dir: pathlib.Path) -> bool:
    """whatweb  (web technology fingerprinting)."""
    if not check_tool("whatweb"):
        return False
    out_file = out_dir / "whatweb.json"
    cmd = ["whatweb", "--log-json", str(out_file), f"http://{target}"]
    return run_command(cmd, out_file, "WhatWeb", file_written_by_tool=True)


def gobuster_scan(target: str, out_dir: pathlib.Path) -> bool:
    """gobuster dir  (directory brute-forcing)."""
    if not check_tool("gobuster"):
        return False
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not pathlib.Path(wordlist).exists():
        cprint(f"  [SKIPPED] Gobuster wordlist not found: {wordlist}", Colors.YELLOW)
        logger.warning("Gobuster wordlist missing: %s", wordlist)
        return False
    out_file = out_dir / "gobuster.txt"
    cmd = [
        "gobuster", "dir",
        "-u", f"http://{target}",
        "-w", wordlist,
        "-o", str(out_file),
    ]
    return run_command(cmd, out_file, "Gobuster", file_written_by_tool=True)


def enum4linux_scan(target: str, out_dir: pathlib.Path) -> bool:
    """enum4linux -a  (SMB/NetBIOS enumeration)."""
    if not check_tool("enum4linux"):
        return False
    out_file = out_dir / "enum4linux.txt"
    cmd = ["enum4linux", "-a", target]
    # enum4linux writes everything to stdout; run_command captures it.
    return run_command(cmd, out_file, "enum4linux")


def nikto_scan(target: str, out_dir: pathlib.Path) -> bool:
    """nikto  (web server vulnerability scanner)."""
    if not check_tool("nikto"):
        return False
    out_file = out_dir / "nikto.txt"
    cmd = [
        "nikto",
        "-h", f"http://{target}",
        "-output", str(out_file),
        "-nointeractive",
    ]
    return run_command(cmd, out_file, "Nikto", file_written_by_tool=True)

def print_summary(results: dict) -> None:
    print()
    cprint("=" * 50, Colors.CYAN, bold=True)
    cprint("  Scan Summary", Colors.BRIGHT_CYAN, bold=True)
    cprint("=" * 50, Colors.CYAN, bold=True)
    for scanner, ok in results.items():
        if ok is None:
            icon, color = "–", Colors.YELLOW   # skipped
        elif ok:
            icon, color = "✓", Colors.BRIGHT_GREEN
        else:
            icon, color = "✗", Colors.RED
        cprint(f"  [{icon}] {scanner}", color)
    cprint("=" * 50, Colors.CYAN, bold=True)


# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="netscan.py",
        description="Automated network assessment tool for authorized targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 netscan.py -t 192.168.56.101
  python3 netscan.py -t 10.0.0.5 --skip-sudo

WARNING: Only run against targets you own or have explicit written permission to test.
""",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="IP",
        help="Target IP address.",
    )
    parser.add_argument(
        "--skip-sudo",
        action="store_true",
        default=False,
        help="Skip scans that require sudo (OS detection, NSE scripts).",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    target: str = args.target
    skip_sudo: bool = args.skip_sudo

    # Create output directory and logging
    out_dir = create_output_directory()
    log_path = out_dir / "scan.log"
    setup_logging(log_path)

    print_banner(target)
    cprint(f"  Output directory : {out_dir}", Colors.BRIGHT_WHITE)
    cprint(f"  Log file         : {log_path}", Colors.BRIGHT_WHITE)
    print()

    logger.info("===== netscan.py START  target=%s  out_dir=%s =====", target, out_dir)

    results: dict = {}

    # ── Scanners ──────────────────────────────────────────────────────────

    # 1. Host Discovery
    ok = host_discovery(target, out_dir)
    results["Host Discovery"] = ok

    # 2. Full Port Scan
    ok = port_scan(target, out_dir)
    results["Full Port Scan"] = ok

    # 3. Service Detection
    ok = service_scan(target, out_dir)
    results["Service Detection"] = ok

    # 4. OS Detection (requires sudo)
    if skip_sudo:
        cprint("\n  [SKIPPED] OS Detection requires sudo (--skip-sudo active).", Colors.YELLOW)
        logger.info("OS Detection skipped (--skip-sudo).")
        results["OS Detection"] = None
    else:
        ok = os_detection(target, out_dir)
        results["OS Detection"] = ok

    # 5. NSE Scripts (requires sudo)
    if skip_sudo:
        cprint("\n  [SKIPPED] NSE Scripts require sudo (--skip-sudo active).", Colors.YELLOW)
        logger.info("NSE Scripts skipped (--skip-sudo).")
        results["NSE Scripts"] = None
    else:
        ok = nse_scan(target, out_dir)
        results["NSE Scripts"] = ok

    # 6. WhatWeb
    ok = whatweb_scan(target, out_dir)
    results["WhatWeb"] = ok

    # 7. Gobuster
    ok = gobuster_scan(target, out_dir)
    results["Gobuster"] = ok

    # 8. enum4linux
    ok = enum4linux_scan(target, out_dir)
    results["enum4linux"] = ok

    # 9. Nikto
    ok = nikto_scan(target, out_dir)
    results["Nikto"] = ok

    # ── End ───────────────────────────────────────────────────────────────

    logger.info("===== netscan.py END =====")

    print_summary(results)
    print_footer(out_dir)

    # Return non-zero only if ALL non-skipped scanners failed
    non_skipped = {k: v for k, v in results.items() if v is not None}
    if non_skipped and all(not v for v in non_skipped.values()):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())