#!/usr/bin/env python3
"""
report.py - HTML Report Generator for netscan.py output
Parses all scanner outputs and produces a single self-contained report.html

Usage:
    python3 report.py -d scans/2026-06-28_22-57-05
"""

import argparse
import datetime
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# PARSERS
# ---------------------------------------------------------------------------

def parse_nmap_xml(filepath: pathlib.Path) -> dict:
    """Parse any nmap XML output file. Returns structured dict."""
    result = {"hosts": [], "error": None}
    if not filepath.exists():
        result["error"] = "File not found"
        return result
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for host in root.findall("host"):
            h = {"ip": "", "status": "", "hostnames": [], "ports": [], "os": [], "scripts": []}

            # Status
            status = host.find("status")
            if status is not None:
                h["status"] = status.get("state", "")

            # IP
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    h["ip"] = addr.get("addr", "")

            # Hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hn in hostnames.findall("hostname"):
                    h["hostnames"].append(hn.get("name", ""))

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    p = {
                        "port": port.get("portid", ""),
                        "protocol": port.get("protocol", ""),
                        "state": "",
                        "service": "",
                        "product": "",
                        "version": "",
                        "scripts": [],
                    }
                    state_el = port.find("state")
                    if state_el is not None:
                        p["state"] = state_el.get("state", "")
                    svc_el = port.find("service")
                    if svc_el is not None:
                        p["service"] = svc_el.get("name", "")
                        p["product"] = svc_el.get("product", "")
                        p["version"] = svc_el.get("version", "")
                    for script in port.findall("script"):
                        p["scripts"].append({
                            "id": script.get("id", ""),
                            "output": script.get("output", ""),
                        })
                    h["ports"].append(p)

            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    h["os"].append({
                        "name": osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", ""),
                    })

            # Host-level scripts
            hostscript = host.find("hostscript")
            if hostscript is not None:
                for script in hostscript.findall("script"):
                    h["scripts"].append({
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    })

            result["hosts"].append(h)
    except Exception as e:
        result["error"] = str(e)
    return result


def parse_whatweb(filepath: pathlib.Path) -> dict:
    """Parse WhatWeb JSON output."""
    result = {"entries": [], "error": None}
    if not filepath.exists():
        result["error"] = "File not found"
        return result
    try:
        text = filepath.read_text(errors="replace").strip()
        if not text:
            result["error"] = "Empty file"
            return result
        # WhatWeb JSON output can be one JSON object per line or a JSON array
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        if not entries:
            # Try as full JSON array
            try:
                entries = json.loads(text)
            except Exception:
                result["error"] = "Could not parse JSON"
                return result
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            e = {"target": entry.get("target", ""), "plugins": {}}
            plugins = entry.get("plugins", {})
            for name, data in plugins.items():
                versions = data.get("version", [])
                strings = data.get("string", [])
                e["plugins"][name] = versions or strings or ["detected"]
            result["entries"].append(e)
    except Exception as ex:
        result["error"] = str(ex)
    return result


def parse_gobuster(filepath: pathlib.Path) -> dict:
    """Parse gobuster text output."""
    result = {"entries": [], "error": None}
    if not filepath.exists():
        result["error"] = "File not found"
        return result
    try:
        lines = filepath.read_text(errors="replace").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("="):
                continue
            # Match lines like:
            #   /index.html          (Status: 200) [Size: 891]
            #   index.html           (Status: 200) [Size: 891]   <- no leading slash
            m = re.match(r"^(/?[^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
            if m:
                path = m.group(1)
                if not path.startswith("/"):
                    path = "/" + path
                result["entries"].append({
                    "path": path,
                    "status": m.group(2),
                    "size": m.group(3) or "",
                })
    except Exception as ex:
        result["error"] = str(ex)
    return result


def parse_enum4linux(filepath: pathlib.Path) -> dict:
    """Parse enum4linux text output into sections."""
    result = {"sections": {}, "error": None}
    if not filepath.exists():
        result["error"] = "File not found"
        return result
    try:
        text = filepath.read_text(errors="replace")
        # Split on section headers like " ===== Section Name ===== "
        parts = re.split(r"\n\s*={5,}[^\n]+={5,}\s*\n", text)
        headers = re.findall(r"\n\s*={5,}\s*([^\n=]+?)\s*={5,}\s*\n", text)
        if headers and parts:
            # First part is pre-header content
            result["sections"]["Info"] = parts[0].strip()
            for i, header in enumerate(headers):
                if i + 1 < len(parts):
                    result["sections"][header.strip()] = parts[i + 1].strip()
        else:
            result["sections"]["Output"] = text.strip()
    except Exception as ex:
        result["error"] = str(ex)
    return result


def parse_nikto(filepath: pathlib.Path) -> dict:
    """Parse nikto text output."""
    result = {"findings": [], "info": [], "error": None}
    if not filepath.exists():
        result["error"] = "File not found"
        return result
    # nikto sometimes saves as nikto.txt.txt due to -output flag + extension
    alt = filepath.parent / (filepath.name + ".txt")
    if not filepath.exists() and alt.exists():
        filepath = alt
    try:
        lines = filepath.read_text(errors="replace").splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("+ "):
                content = line[2:].strip()
                # Findings usually mention OSVDB, CVE, or specific vulnerabilities
                if any(kw in content for kw in ["OSVDB", "CVE", "vuln", "Vuln",
                                                  "allow", "Allow", "header", "Header",
                                                  "error", "Error", "risk", "Risk",
                                                  "inject", "XSS", "SQL"]):
                    result["findings"].append(content)
                else:
                    result["info"].append(content)
            elif line.startswith("-"):
                result["info"].append(line)
    except Exception as ex:
        result["error"] = str(ex)
    return result


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def port_state_color(state: str) -> str:
    return {"open": "#22c55e", "closed": "#ef4444", "filtered": "#f59e0b"}.get(state, "#94a3b8")


def severity_badge(text: str) -> str:
    """Guess severity from nikto finding text and return a colored badge."""
    text_l = text.lower()
    if any(w in text_l for w in ["sql", "xss", "inject", "rce", "exec", "remote"]):
        return '<span class="badge badge-critical">CRITICAL</span>'
    if any(w in text_l for w in ["osvdb", "cve", "vuln", "dangerous", "risk"]):
        return '<span class="badge badge-high">HIGH</span>'
    if any(w in text_l for w in ["allow", "header", "cookie", "cors", "method"]):
        return '<span class="badge badge-medium">MEDIUM</span>'
    return '<span class="badge badge-low">INFO</span>'


def esc(text: str) -> str:
    """HTML-escape a string."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# HTML SECTION BUILDERS
# ---------------------------------------------------------------------------

def section(title: str, icon: str, content: str, scan_id: str) -> str:
    sid = scan_id.replace(" ", "_")
    return f"""
<div class="card" id="sec-{sid}">
  <div class="card-header" onclick="toggle('{sid}')">
    <span class="card-icon">{icon}</span>
    <span class="card-title">{title}</span>
    <span class="chevron" id="chev-{sid}">▼</span>
  </div>
  <div class="card-body" id="body-{sid}">
    {content}
  </div>
</div>"""


def error_block(msg: str) -> str:
    return f'<div class="error-block">⚠ {esc(msg)}</div>'


def build_host_discovery(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    if not data["hosts"]:
        return "<p class='empty'>No hosts found.</p>"
    rows = ""
    for h in data["hosts"]:
        status_color = "#22c55e" if h["status"] == "up" else "#ef4444"
        hostnames = ", ".join(h["hostnames"]) or "—"
        rows += f"""
        <tr>
          <td><code>{esc(h['ip'])}</code></td>
          <td><span style="color:{status_color};font-weight:600">{esc(h['status'])}</span></td>
          <td>{esc(hostnames)}</td>
        </tr>"""
    return f"""
    <table>
      <thead><tr><th>IP Address</th><th>Status</th><th>Hostnames</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def build_ports(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    all_ports = []
    for h in data["hosts"]:
        for p in h["ports"]:
            if p["state"] == "open":
                all_ports.append((h["ip"], p))
    if not all_ports:
        return "<p class='empty'>No open ports found.</p>"
    rows = ""
    for ip, p in all_ports:
        color = port_state_color(p["state"])
        svc = f"{esc(p['product'])} {esc(p['version'])}".strip() or esc(p["service"])
        rows += f"""
        <tr>
          <td><code>{esc(ip)}</code></td>
          <td><strong>{esc(p['port'])}</strong></td>
          <td>{esc(p['protocol'].upper())}</td>
          <td><span style="color:{color};font-weight:600">{esc(p['state'])}</span></td>
          <td>{esc(p['service'])}</td>
          <td>{svc}</td>
        </tr>"""
    return f"""
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def build_services(data: dict) -> str:
    return build_ports(data)  # Same structure, richer version info


def build_os(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    rows = ""
    for h in data["hosts"]:
        if not h["os"]:
            continue
        for os in h["os"][:3]:  # top 3 matches
            bar_w = int(os["accuracy"]) if os["accuracy"].isdigit() else 0
            rows += f"""
            <tr>
              <td><code>{esc(h['ip'])}</code></td>
              <td>{esc(os['name'])}</td>
              <td>
                <div class="acc-bar-bg">
                  <div class="acc-bar-fill" style="width:{bar_w}%"></div>
                </div>
                <span class="acc-label">{esc(os['accuracy'])}%</span>
              </td>
            </tr>"""
    if not rows:
        return "<p class='empty'>No OS matches found (may require sudo/root).</p>"
    return f"""
    <table>
      <thead><tr><th>Host</th><th>OS Match</th><th>Accuracy</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def build_scripts(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    blocks = ""
    for h in data["hosts"]:
        # Host-level scripts
        for s in h["scripts"]:
            blocks += f"""
            <div class="script-block">
              <div class="script-id">{esc(s['id'])}</div>
              <pre class="script-output">{esc(s['output'])}</pre>
            </div>"""
        # Port-level scripts
        for p in h["ports"]:
            for s in p["scripts"]:
                blocks += f"""
                <div class="script-block">
                  <div class="script-id">{esc(p['port'])}/{esc(p['protocol'])} — {esc(s['id'])}</div>
                  <pre class="script-output">{esc(s['output'])}</pre>
                </div>"""
    if not blocks:
        return "<p class='empty'>No script results found.</p>"
    return blocks


def build_whatweb(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    if not data["entries"]:
        return "<p class='empty'>No WhatWeb results.</p>"
    blocks = ""
    for entry in data["entries"]:
        tags = ""
        for name, values in entry["plugins"].items():
            val_str = ", ".join(str(v) for v in values[:3])
            tags += f'<span class="tech-tag"><strong>{esc(name)}</strong>'
            if val_str and val_str != "detected":
                tags += f': {esc(val_str)}'
            tags += '</span>'
        blocks += f"""
        <div class="whatweb-entry">
          <div class="whatweb-target">{esc(entry['target'])}</div>
          <div class="tech-tags">{tags}</div>
        </div>"""
    return blocks


def build_gobuster(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    if not data["entries"]:
        return "<p class='empty'>No directories found.</p>"
    rows = ""
    for e in data["entries"]:
        status = e["status"]
        color = {"200": "#22c55e", "301": "#3b82f6", "302": "#3b82f6",
                 "403": "#f59e0b", "404": "#ef4444"}.get(status, "#94a3b8")
        rows += f"""
        <tr>
          <td><code>{esc(e['path'])}</code></td>
          <td><span style="color:{color};font-weight:600">{esc(status)}</span></td>
          <td>{esc(e['size']) or '—'}</td>
        </tr>"""
    return f"""
    <table>
      <thead><tr><th>Path</th><th>Status</th><th>Size (bytes)</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def build_enum4linux(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    if not data["sections"]:
        return "<p class='empty'>No enum4linux output.</p>"
    blocks = ""
    for title, content in data["sections"].items():
        if not content.strip():
            continue
        blocks += f"""
        <div class="enum-section">
          <div class="enum-title">{esc(title)}</div>
          <pre class="enum-content">{esc(content[:3000])}</pre>
        </div>"""
    return blocks or "<p class='empty'>No enum4linux output.</p>"


def build_nikto(data: dict) -> str:
    if data["error"]:
        return error_block(data["error"])
    html = ""
    if data["findings"]:
        rows = ""
        for f in data["findings"]:
            rows += f"<tr><td>{severity_badge(f)}</td><td>{esc(f)}</td></tr>"
        html += f"""
        <h3 class="sub-heading">Potential Vulnerabilities</h3>
        <table>
          <thead><tr><th>Severity</th><th>Finding</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    if data["info"]:
        rows = ""
        for f in data["info"]:
            rows += f"<tr><td>{esc(f)}</td></tr>"
        html += f"""
        <h3 class="sub-heading" style="margin-top:1.5rem">Informational</h3>
        <table>
          <thead><tr><th>Detail</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    if not html:
        return "<p class='empty'>No Nikto findings.</p>"
    return html


# ---------------------------------------------------------------------------
# STAT COUNTERS
# ---------------------------------------------------------------------------

def count_open_ports(ports_data: dict) -> int:
    count = 0
    for h in ports_data.get("hosts", []):
        count += sum(1 for p in h["ports"] if p["state"] == "open")
    return count


def count_hosts_up(disc_data: dict) -> int:
    return sum(1 for h in disc_data.get("hosts", []) if h["status"] == "up")


# ---------------------------------------------------------------------------
# FULL HTML GENERATOR
# ---------------------------------------------------------------------------

def generate_html(scan_dir: pathlib.Path, data: dict, target: str, scan_time: str) -> str:
    open_ports  = count_open_ports(data["ports"])
    hosts_up    = count_hosts_up(data["discovery"])
    nikto_vulns = len(data["nikto"]["findings"])
    web_techs   = sum(len(e["plugins"]) for e in data["whatweb"]["entries"])
    dirs_found  = len(data["gobuster"]["entries"])

    sections_html = (
        section("Host Discovery",   "🔍", build_host_discovery(data["discovery"]), "host_discovery") +
        section("Full Port Scan",   "🚪", build_ports(data["ports"]),              "port_scan") +
        section("Service Detection","⚙️",  build_services(data["services"]),        "services") +
        section("OS Detection",     "💻", build_os(data["os"]),                    "os") +
        section("NSE Scripts",      "📜", build_scripts(data["scripts"]),           "scripts") +
        section("WhatWeb",          "🌐", build_whatweb(data["whatweb"]),           "whatweb") +
        section("Gobuster",         "📂", build_gobuster(data["gobuster"]),         "gobuster") +
        section("enum4linux",       "🔓", build_enum4linux(data["enum4linux"]),     "enum4linux") +
        section("Nikto",            "🛡️",  build_nikto(data["nikto"]),              "nikto")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>INAVRF Scan Report — {esc(target)}</title>
<style>
  :root {{
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #21262d;
    --border:    #30363d;
    --accent:    #00d4aa;
    --accent2:   #0ea5e9;
    --text:      #e6edf3;
    --text-muted:#8b949e;
    --red:       #ef4444;
    --green:     #22c55e;
    --yellow:    #f59e0b;
    --blue:      #3b82f6;
    --radius:    8px;
    --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    --font-body: 'Inter', system-ui, -apple-system, sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-body);
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 4rem;
  }}

  /* ── HEADER ── */
  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 3rem 2rem 2rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -60px; left: -60px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(0,212,170,0.08) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-inner {{
    max-width: 1100px;
    margin: 0 auto;
  }}
  .logo {{
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 4px;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 1rem;
    opacity: 0.8;
  }}
  h1 {{
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 0.4rem;
  }}
  h1 span {{ color: var(--accent); }}
  .header-meta {{
    color: var(--text-muted);
    font-size: 13px;
    font-family: var(--font-mono);
    margin-top: 0.5rem;
  }}

  /* ── STATS BAR ── */
  .stats-bar {{
    max-width: 1100px;
    margin: 2rem auto 0;
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    padding: 0 2rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.2rem 1rem;
    text-align: center;
  }}
  .stat-card:first-child {{ border-top: 2px solid var(--accent); }}
  .stat-number {{
    font-size: 2rem;
    font-weight: 700;
    font-family: var(--font-mono);
    color: var(--accent);
    line-height: 1;
  }}
  .stat-label {{
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 0.4rem;
  }}

  /* ── MAIN CONTENT ── */
  .main {{
    max-width: 1100px;
    margin: 2.5rem auto 0;
    padding: 0 2rem;
  }}

  /* ── CARDS ── */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1rem;
    overflow: hidden;
  }}
  .card-header {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 1.25rem;
    cursor: pointer;
    user-select: none;
    transition: background 0.15s;
    border-bottom: 1px solid transparent;
  }}
  .card-header:hover {{ background: var(--surface2); }}
  .card-icon {{ font-size: 1.1rem; }}
  .card-title {{
    flex: 1;
    font-weight: 600;
    font-size: 15px;
    letter-spacing: 0.2px;
  }}
  .chevron {{
    color: var(--text-muted);
    font-size: 12px;
    transition: transform 0.2s;
  }}
  .chevron.open {{ transform: rotate(180deg); }}
  .card-body {{
    padding: 1.25rem;
    border-top: 1px solid var(--border);
  }}
  .card-body.hidden {{ display: none; }}

  /* ── TABLES ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  thead tr {{
    background: var(--surface2);
  }}
  th {{
    text-align: left;
    padding: 0.6rem 0.85rem;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    font-weight: 600;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  code {{
    font-family: var(--font-mono);
    font-size: 12px;
    background: var(--surface2);
    padding: 1px 5px;
    border-radius: 4px;
    color: var(--accent2);
  }}

  /* ── ACCURACY BAR ── */
  .acc-bar-bg {{
    display: inline-block;
    width: 100px;
    height: 6px;
    background: var(--surface2);
    border-radius: 3px;
    vertical-align: middle;
    margin-right: 6px;
  }}
  .acc-bar-fill {{
    height: 6px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 3px;
  }}
  .acc-label {{
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
  }}

  /* ── SCRIPTS ── */
  .script-block {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 0.75rem;
    overflow: hidden;
  }}
  .script-id {{
    background: rgba(0,212,170,0.08);
    border-bottom: 1px solid var(--border);
    padding: 0.5rem 1rem;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent);
    font-weight: 600;
  }}
  .script-output {{
    padding: 0.75rem 1rem;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 250px;
    overflow-y: auto;
  }}

  /* ── WHATWEB ── */
  .whatweb-entry {{ margin-bottom: 1rem; }}
  .whatweb-target {{
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent2);
    margin-bottom: 0.5rem;
  }}
  .tech-tags {{ display: flex; flex-wrap: wrap; gap: 0.4rem; }}
  .tech-tag {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 12px;
    color: var(--text-muted);
  }}
  .tech-tag strong {{ color: var(--text); }}

  /* ── ENUM4LINUX ── */
  .enum-section {{ margin-bottom: 1.25rem; }}
  .enum-title {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--accent);
    margin-bottom: 0.4rem;
  }}
  .enum-content {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
  }}

  /* ── BADGES ── */
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
  .badge-high     {{ background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
  .badge-medium   {{ background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }}
  .badge-low      {{ background: rgba(148,163,184,0.1); color: #94a3b8; border: 1px solid rgba(148,163,184,0.2); }}

  /* ── MISC ── */
  .error-block {{
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    color: #fca5a5;
    font-size: 13px;
  }}
  .empty {{
    color: var(--text-muted);
    font-style: italic;
    font-size: 13px;
  }}
  .sub-heading {{
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 0.75rem;
  }}

  /* ── FOOTER ── */
  .footer {{
    max-width: 1100px;
    margin: 3rem auto 0;
    padding: 0 2rem;
    border-top: 1px solid var(--border);
    padding-top: 1.5rem;
    color: var(--text-muted);
    font-size: 12px;
    font-family: var(--font-mono);
    display: flex;
    justify-content: space-between;
  }}

  @media (max-width: 700px) {{
    .stats-bar {{ grid-template-columns: repeat(2, 1fr); }}
    h1 {{ font-size: 1.4rem; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">INAVRF // Network Assessment Report</div>
    <h1>Scan Report — <span>{esc(target)}</span></h1>
    <div class="header-meta">
      Generated: {esc(scan_time)} &nbsp;|&nbsp; Scan folder: {esc(str(scan_dir.name))}
    </div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat-card">
    <div class="stat-number">{hosts_up}</div>
    <div class="stat-label">Hosts Up</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{open_ports}</div>
    <div class="stat-label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{nikto_vulns}</div>
    <div class="stat-label">Nikto Findings</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{web_techs}</div>
    <div class="stat-label">Web Technologies</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{dirs_found}</div>
    <div class="stat-label">Dirs Found</div>
  </div>
</div>

<div class="main">
  {sections_html}
</div>

<div class="footer">
  <span>INAVRF netscan.py + report.py</span>
  <span>Target: {esc(target)} | {esc(scan_time)}</span>
</div>

<script>
  function toggle(id) {{
    const body  = document.getElementById('body-' + id);
    const chev  = document.getElementById('chev-' + id);
    body.classList.toggle('hidden');
    chev.classList.toggle('open');
  }}
  // Start all sections open
  document.querySelectorAll('.card-body').forEach(el => el.classList.remove('hidden'));
  document.querySelectorAll('.chevron').forEach(el => el.classList.add('open'));
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="report.py",
        description="Generate an HTML report from a netscan.py output folder.",
    )
    parser.add_argument(
        "-d", "--dir",
        required=True,
        metavar="SCAN_DIR",
        help="Path to the timestamped scan folder (e.g. scans/2026-06-28_22-57-05)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Output HTML file path (default: <SCAN_DIR>/report.html)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scan_dir = pathlib.Path(args.dir).resolve()

    if not scan_dir.exists() or not scan_dir.is_dir():
        print(f"[ERROR] Directory not found: {scan_dir}", file=sys.stderr)
        return 1

    out_path = pathlib.Path(args.output) if args.output else scan_dir / "report.html"

    # Guess target from scan.log or folder name
    target = "unknown"
    log_path = scan_dir / "scan.log"
    if log_path.exists():
        for line in log_path.read_text(errors="replace").splitlines():
            m = re.search(r"target=(\S+)", line)
            if m:
                target = m.group(1)
                break

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[*] Parsing scan outputs in: {scan_dir}")

    # Parse all outputs
    # nikto may be saved as nikto.txt or nikto.txt.txt
    nikto_path = scan_dir / "nikto.txt"
    if not nikto_path.exists() and (scan_dir / "nikto.txt.txt").exists():
        nikto_path = scan_dir / "nikto.txt.txt"

    data = {
        "discovery":  parse_nmap_xml(scan_dir / "host_discovery.xml"),
        "ports":      parse_nmap_xml(scan_dir / "ports.xml"),
        "services":   parse_nmap_xml(scan_dir / "services.xml"),
        "os":         parse_nmap_xml(scan_dir / "os.xml"),
        "scripts":    parse_nmap_xml(scan_dir / "scripts.xml"),
        "whatweb":    parse_whatweb(scan_dir / "whatweb.json"),
        "gobuster":   parse_gobuster(scan_dir / "gobuster.txt"),
        "enum4linux": parse_enum4linux(scan_dir / "enum4linux.txt"),
        "nikto":      parse_nikto(nikto_path),
    }

    print("[*] Generating HTML report ...")
    html = generate_html(scan_dir, data, target, scan_time)
    out_path.write_text(html, encoding="utf-8")
    print(f"[✓] Report saved to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())