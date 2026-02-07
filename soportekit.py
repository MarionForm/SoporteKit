#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SoporteKit - Script de diagnóstico rápido para Helpdesk / Soporte Técnico
Genera un informe TXT + JSON con:
- Info del sistema (SO, CPU, RAM, disco)
- Info de red (IPs, gateway, DNS)
- Tests de conectividad (ping, DNS, HTTP)
- Top procesos (opcional con psutil)
- Logs de errores recientes en Windows (si existe wevtutil)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---- Optional dependency ----
try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except Exception:
    psutil = None  # type: ignore
    HAS_PSUTIL = False


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    """Run a command and return (exit_code, combined_output)."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"Timeout running: {' '.join(cmd)}"
    except Exception as e:
        return 1, f"Error running {' '.join(cmd)}: {e}"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def bytes_to_gb(n: int | float) -> float:
    return round(float(n) / (1024 ** 3), 2)


def get_basic_system_info() -> dict:
    info = {
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        "os": platform.system(),
        "os_version": platform.version(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
    }

    # CPU / RAM / Disk - best effort, psutil improves it
    if HAS_PSUTIL:
        info["cpu"] = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "cpu_percent_now": psutil.cpu_percent(interval=0.5),
        }
        vm = psutil.virtual_memory()
        info["ram"] = {
            "total_gb": bytes_to_gb(vm.total),
            "used_gb": bytes_to_gb(vm.used),
            "percent": vm.percent,
        }
        du = psutil.disk_usage(str(Path.home().anchor))
        info["disk_root"] = {
            "total_gb": bytes_to_gb(du.total),
            "used_gb": bytes_to_gb(du.used),
            "free_gb": bytes_to_gb(du.free),
            "percent": du.percent,
        }
    else:
        info["cpu"] = {"note": "Install psutil for more detailed CPU/RAM/DISK info."}
        info["ram"] = {"note": "Install psutil for RAM usage."}
        info["disk_root"] = {"note": "Install psutil for disk usage."}

    return info


def parse_ipconfig_windows(text: str) -> dict:
    # Very simplified parsing for IPv4, gateway and DNS from ipconfig /all
    ipv4 = re.findall(r"IPv4 Address[.\s]*:\s*([\d\.]+)", text)
    gw = re.findall(r"Default Gateway[.\s]*:\s*([\d\.]+)", text)
    dns = re.findall(r"DNS Servers[.\s]*:\s*([\d\.]+)", text)

    # Also capture subsequent DNS lines (indented)
    lines = text.splitlines()
    dns_all = []
    capture_dns = False
    for line in lines:
        if "DNS Servers" in line:
            capture_dns = True
            m = re.search(r"DNS Servers[.\s]*:\s*([\d\.]+)", line)
            if m:
                dns_all.append(m.group(1))
            continue
        if capture_dns:
            if line.strip() == "":
                capture_dns = False
                continue
            m2 = re.search(r"^\s+([\d\.]+)\s*$", line)
            if m2:
                dns_all.append(m2.group(1))

    return {
        "ipv4": sorted(set(ipv4)),
        "gateway": sorted(set([x for x in gw if x.strip()])),
        "dns": sorted(set(dns_all or dns)),
    }


def get_network_info() -> dict:
    data: dict = {"interfaces": [], "ipv4": [], "gateway": [], "dns": []}

    if HAS_PSUTIL:
        addrs = psutil.net_if_addrs()
        for ifname, addrlist in addrs.items():
            iface = {"name": ifname, "ips": []}
            for a in addrlist:
                if getattr(a, "family", None) == socket.AF_INET:
                    iface["ips"].append(a.address)
                    data["ipv4"].append(a.address)
            if iface["ips"]:
                data["interfaces"].append(iface)
        data["ipv4"] = sorted(set(data["ipv4"]))

    # OS-specific best-effort for gateway/dns
    if is_windows():
        code, out = run_cmd(["ipconfig", "/all"], timeout=20)
        data["raw_ipconfig_ok"] = (code == 0)
        if code == 0:
            parsed = parse_ipconfig_windows(out)
            data["gateway"] = parsed["gateway"]
            data["dns"] = parsed["dns"]
            # merge ipv4 if not present
            if not data["ipv4"]:
                data["ipv4"] = parsed["ipv4"]
    elif is_linux():
        # gateway
        code, out = run_cmd(["ip", "route"], timeout=10)
        if code == 0:
            m = re.search(r"default via ([\d\.]+)", out)
            if m:
                data["gateway"] = [m.group(1)]
        # DNS
        try:
            resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
            dns = re.findall(r"nameserver\s+([\d\.]+)", resolv)
            data["dns"] = sorted(set(dns))
        except Exception:
            pass
    elif is_macos():
        # gateway
        code, out = run_cmd(["route", "-n", "get", "default"], timeout=10)
        if code == 0:
            m = re.search(r"gateway:\s+([\d\.]+)", out)
            if m:
                data["gateway"] = [m.group(1)]
        # DNS
        code, out = run_cmd(["scutil", "--dns"], timeout=10)
        if code == 0:
            dns = re.findall(r"nameserver\[\d+\]\s*:\s*([\d\.]+)", out)
            data["dns"] = sorted(set(dns))

    return data


def ping(host: str, count: int = 2) -> dict:
    if is_windows():
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    code, out = run_cmd(cmd, timeout=15)
    return {"target": host, "ok": code == 0, "exit_code": code, "output": out[:4000]}


def dns_lookup(hostname: str) -> dict:
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ok": True, "ip": ip}
    except Exception as e:
        return {"hostname": hostname, "ok": False, "error": str(e)}


def http_test(url: str, timeout: int = 8) -> dict:
    try:
        req = Request(url, headers={"User-Agent": "SoporteKit/1.0"})
        with urlopen(req, timeout=timeout) as r:
            return {"url": url, "ok": True, "status": getattr(r, "status", None)}
    except HTTPError as e:
        return {"url": url, "ok": False, "http_error": int(e.code)}
    except URLError as e:
        return {"url": url, "ok": False, "url_error": str(e.reason)}
    except Exception as e:
        return {"url": url, "ok": False, "error": str(e)}


def get_top_processes(limit: int = 10) -> dict:
    if not HAS_PSUTIL:
        return {"ok": False, "note": "psutil not installed"}

    procs = []
    for p in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            cpu = p.cpu_percent(interval=0.0)
            mem = p.memory_info().rss
            procs.append({
                "pid": p.info.get("pid"),
                "name": p.info.get("name"),
                "user": p.info.get("username"),
                "cpu_percent": cpu,
                "ram_rss_gb": bytes_to_gb(mem),
            })
        except Exception:
            continue

    procs_sorted_cpu = sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:limit]
    procs_sorted_ram = sorted(procs, key=lambda x: x["ram_rss_gb"], reverse=True)[:limit]
    return {"ok": True, "top_cpu": procs_sorted_cpu, "top_ram": procs_sorted_ram}


def windows_recent_errors(log_name: str, max_events: int = 30) -> dict:
    if not is_windows():
        return {"ok": False, "note": "Only available on Windows"}
    if shutil.which("wevtutil") is None:
        return {"ok": False, "note": "wevtutil not found"}

    # Query last N events with level=2 (Error)
    # XPath: Level=2 -> Error, Level=1 -> Critical
    query = f"*[System[(Level=1 or Level=2)]]"
    cmd = ["wevtutil", "qe", log_name, f"/q:{query}", f"/c:{max_events}", "/f:text"]
    code, out = run_cmd(cmd, timeout=20)
    return {"ok": code == 0, "log": log_name, "exit_code": code, "output": out[:12000]}


def build_report() -> dict:
    system = get_basic_system_info()
    net = get_network_info()

    # Decide a “gateway” to ping if available
    gw = net.get("gateway") or []
    gw_target = gw[0] if gw else None

    tests = {
        "ping_gateway": ping(gw_target, count=2) if gw_target else {"ok": False, "note": "No gateway detected"},
        "ping_internet_ip": ping("1.1.1.1", count=2),
        "dns_lookup_google": dns_lookup("google.com"),
        "http_google": http_test("https://www.google.com"),
        "http_cloudflare": http_test("https://1.1.1.1"),
    }

    extras = {
        "top_processes": get_top_processes(limit=10),
    }

    if is_windows():
        extras["windows_logs_system"] = windows_recent_errors("System", max_events=25)
        extras["windows_logs_application"] = windows_recent_errors("Application", max_events=25)

    return {
        "system": system,
        "network": net,
        "tests": tests,
        "extras": extras,
    }


def render_txt(report: dict) -> str:
    sysi = report["system"]
    net = report["network"]
    tests = report["tests"]
    extras = report["extras"]

    def line(title: str) -> str:
        return f"\n{'='*8} {title} {'='*8}\n"

    txt = []
    txt.append("SOPORTEKIT - INFORME DE DIAGNÓSTICO\n")
    txt.append(f"Fecha: {sysi.get('timestamp')}\nHost: {sysi.get('hostname')} | Usuario: {sysi.get('user')}\n")

    txt.append(line("SISTEMA"))
    txt.append(f"OS: {sysi.get('os')} {sysi.get('release')} ({sysi.get('architecture')})\n")
    txt.append(f"OS build/version: {sysi.get('os_version')}\n")
    txt.append(f"Python: {sysi.get('python')}\n")
    txt.append(f"CPU: {json.dumps(sysi.get('cpu', {}), ensure_ascii=False)}\n")
    txt.append(f"RAM: {json.dumps(sysi.get('ram', {}), ensure_ascii=False)}\n")
    txt.append(f"DISK: {json.dumps(sysi.get('disk_root', {}), ensure_ascii=False)}\n")

    txt.append(line("RED"))
    txt.append(f"IPv4: {', '.join(net.get('ipv4') or []) or 'N/A'}\n")
    txt.append(f"Gateway: {', '.join(net.get('gateway') or []) or 'N/A'}\n")
    txt.append(f"DNS: {', '.join(net.get('dns') or []) or 'N/A'}\n")
    if net.get("interfaces"):
        txt.append("Interfaces:\n")
        for i in net["interfaces"]:
            txt.append(f" - {i['name']}: {', '.join(i.get('ips', []))}\n")

    txt.append(line("TESTS"))
    for k, v in tests.items():
        ok = v.get("ok")
        txt.append(f"[{k}] OK={ok}\n")
        # keep it readable
        if "status" in v:
            txt.append(f"  status: {v.get('status')}\n")
        if "ip" in v:
            txt.append(f"  ip: {v.get('ip')}\n")
        if "note" in v:
            txt.append(f"  note: {v.get('note')}\n")
        if "output" in v and v["output"]:
            txt.append("  output:\n")
            txt.append(textwrap.indent(v["output"][:1200], "    "))
            txt.append("\n")

    txt.append(line("EXTRAS"))
    tp = extras.get("top_processes", {})
    if tp.get("ok"):
        txt.append("Top CPU:\n")
        for p in tp.get("top_cpu", []):
            txt.append(f" - {p['name']} (PID {p['pid']}): CPU {p['cpu_percent']}% | RAM {p['ram_rss_gb']} GB\n")
        txt.append("Top RAM:\n")
        for p in tp.get("top_ram", []):
            txt.append(f" - {p['name']} (PID {p['pid']}): RAM {p['ram_rss_gb']} GB | CPU {p['cpu_percent']}%\n")
    else:
        txt.append(f"Top procesos: {tp.get('note', 'N/A')}\n")

    if is_windows():
        for key in ("windows_logs_system", "windows_logs_application"):
            log = extras.get(key, {})
            txt.append(f"\n{key} OK={log.get('ok')}\n")
            if log.get("note"):
                txt.append(f"  note: {log.get('note')}\n")
            if log.get("output"):
                txt.append("  output (recortado):\n")
                txt.append(textwrap.indent(log["output"][:3000], "    "))
                txt.append("\n")

    return "".join(txt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SoporteKit - Diagnóstico rápido (TXT + JSON)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--out", default="soportekit_reports", help="Carpeta de salida (default: soportekit_reports)")
    parser.add_argument("--open", action="store_true", help="Abrir la carpeta de salida al final (Windows)")
    args = parser.parse_args()

    base = Path(args.out).expanduser().resolve()
    folder = base / f"report_{now_stamp()}"
    safe_mkdir(folder)

    report = build_report()

    # Save JSON
    json_path = folder / "report.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Save TXT
    txt_path = folder / "report.txt"
    txt_path.write_text(render_txt(report), encoding="utf-8")

    print(f"[OK] Report generado en:\n - {txt_path}\n - {json_path}")

    if args.open and is_windows():
        os.startfile(str(folder))  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
