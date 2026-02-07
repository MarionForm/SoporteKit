#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SoporteKit - Script de diagnóstico rápido para Helpdesk / Soporte Técnico / Docencia.

Genera un informe TXT + JSON con:
- Info del sistema (OS, CPU, RAM, disco) [mejor con psutil]
- Info de red (IPs, gateway, DNS)
- Tests de conectividad (ping, DNS, HTTP)
- Top procesos (opcional con psutil)
- Logs de errores recientes en Windows (si existe wevtutil)

Uso:
  python soportekit.py
  python soportekit.py --open
  python soportekit.py --out C:\\temp\\reports
  python soportekit.py --no-logs
  python soportekit.py --no-tests
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


# ----------------------------
# Helpers
# ----------------------------

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


def strip_control_chars(s: str) -> str:
    """Remove most control chars but keep \n \r \t."""
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", s)


def safe_text(s: str, max_len: int | None = None) -> str:
    s2 = strip_control_chars(s)
    if max_len is not None:
        return s2[:max_len]
    return s2


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    """
    Run a command and return (exit_code, combined_output).
    Robust decoding on Windows (avoids cp1252 UnicodeDecodeError).
    """
    # First attempt: force UTF-8 + replace undecodable chars
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, safe_text(out).strip()

    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"Timeout running: {' '.join(cmd)}"
    except Exception:
        # Fallback: read as bytes then decode safely
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=False,
                timeout=timeout,
                shell=False,
            )
            outb = (p.stdout or b"") + (p.stderr or b"")
            out = outb.decode("utf-8", errors="replace")
            return p.returncode, safe_text(out).strip()
        except Exception as e2:
            return 1, f"Error running {' '.join(cmd)}: {e2}"


# ----------------------------
# Data collectors
# ----------------------------

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

    if HAS_PSUTIL:
        try:
            info["cpu"] = {
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "cpu_percent_now": psutil.cpu_percent(interval=0.5),
            }
        except Exception:
            info["cpu"] = {"note": "psutil cpu info failed"}

        try:
            vm = psutil.virtual_memory()
            info["ram"] = {
                "total_gb": bytes_to_gb(vm.total),
                "used_gb": bytes_to_gb(vm.used),
                "percent": vm.percent,
            }
        except Exception:
            info["ram"] = {"note": "psutil ram info failed"}

        try:
            # Root drive (Windows: C:\, Linux/Mac: /)
            root_path = str(Path.home().anchor) if is_windows() else "/"
            du = psutil.disk_usage(root_path)
            info["disk_root"] = {
                "path": root_path,
                "total_gb": bytes_to_gb(du.total),
                "used_gb": bytes_to_gb(du.used),
                "free_gb": bytes_to_gb(du.free),
                "percent": du.percent,
            }
        except Exception:
            info["disk_root"] = {"note": "psutil disk info failed"}
    else:
        info["cpu"] = {"note": "Install psutil for CPU/RAM/DISK details. (pip install psutil)"}
        info["ram"] = {"note": "Install psutil for RAM usage. (pip install psutil)"}
        info["disk_root"] = {"note": "Install psutil for disk usage. (pip install psutil)"}

    return info


def parse_ipconfig_windows(text: str) -> dict:
    # Basic parsing for IPv4, gateway and DNS from ipconfig /all
    ipv4 = re.findall(r"IPv4 Address[.\s]*:\s*([\d\.]+)", text)
    gw = re.findall(r"Default Gateway[.\s]*:\s*([\d\.]+)", text)

    lines = text.splitlines()
    dns_all: list[str] = []
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
        "dns": sorted(set(dns_all)),
    }


def get_network_info(timeout: int = 15) -> dict:
    data: dict = {"interfaces": [], "ipv4": [], "gateway": [], "dns": []}

    # Interfaces + IPv4 via psutil if available
    if HAS_PSUTIL:
        try:
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
        except Exception:
            pass

    # OS-specific best-effort for gateway/dns
    if is_windows():
        code, out = run_cmd(["ipconfig", "/all"], timeout=timeout)
        data["raw_ipconfig_ok"] = (code == 0)
        if code == 0:
            parsed = parse_ipconfig_windows(out)
            data["gateway"] = parsed["gateway"]
            data["dns"] = parsed["dns"]
            if not data["ipv4"]:
                data["ipv4"] = parsed["ipv4"]

    elif is_linux():
        code, out = run_cmd(["ip", "route"], timeout=timeout)
        if code == 0:
            m = re.search(r"default via ([\d\.]+)", out)
            if m:
                data["gateway"] = [m.group(1)]

        try:
            resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
            dns = re.findall(r"nameserver\s+([\d\.]+)", resolv)
            data["dns"] = sorted(set(dns))
        except Exception:
            pass

    elif is_macos():
        code, out = run_cmd(["route", "-n", "get", "default"], timeout=timeout)
        if code == 0:
            m = re.search(r"gateway:\s+([\d\.]+)", out)
            if m:
                data["gateway"] = [m.group(1)]

        code, out = run_cmd(["scutil", "--dns"], timeout=timeout)
        if code == 0:
            dns = re.findall(r"nameserver\[\d+\]\s*:\s*([\d\.]+)", out)
            data["dns"] = sorted(set(dns))

    return data


# ----------------------------
# Tests
# ----------------------------

def ping(host: str, count: int = 2, timeout: int = 15) -> dict:
    if not host:
        return {"target": host, "ok": False, "note": "Empty target"}

    if is_windows():
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]

    code, out = run_cmd(cmd, timeout=timeout)
    return {"target": host, "ok": code == 0, "exit_code": code, "output": safe_text(out, 4000)}


def dns_lookup(hostname: str) -> dict:
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ok": True, "ip": ip}
    except Exception as e:
        return {"hostname": hostname, "ok": False, "error": str(e)}


def http_test(url: str, timeout: int = 8) -> dict:
    try:
        req = Request(url, headers={"User-Agent": "SoporteKit/1.1"})
        with urlopen(req, timeout=timeout) as r:
            status = getattr(r, "status", None)
            return {"url": url, "ok": True, "status": status}
    except HTTPError as e:
        return {"url": url, "ok": False, "http_error": int(e.code)}
    except URLError as e:
        return {"url": url, "ok": False, "url_error": str(e.reason)}
    except Exception as e:
        return {"url": url, "ok": False, "error": str(e)}


def get_top_processes(limit: int = 10) -> dict:
    if not HAS_PSUTIL:
        return {"ok": False, "note": "psutil not installed (pip install psutil)"}

    procs = []
    # Warm-up cpu_percent readings
    try:
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=0.0)
            except Exception:
                pass
    except Exception:
        pass

    # Small wait for meaningful CPU deltas
    try:
        psutil.cpu_percent(interval=0.2)
    except Exception:
        pass

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


# ----------------------------
# Windows logs (optional)
# ----------------------------

def windows_recent_errors(log_name: str, max_events: int = 30, timeout: int = 20) -> dict:
    if not is_windows():
        return {"ok": False, "note": "Only available on Windows"}
    if shutil.which("wevtutil") is None:
        return {"ok": False, "note": "wevtutil not found"}

    # Level=1 Critical, Level=2 Error
    query = "*[System[(Level=1 or Level=2)]]"
    cmd = ["wevtutil", "qe", log_name, f"/q:{query}", f"/c:{max_events}", "/f:text"]
    code, out = run_cmd(cmd, timeout=timeout)
    return {
        "ok": code == 0,
        "log": log_name,
        "exit_code": code,
        "output": safe_text(out, 12000),
    }


# ----------------------------
# Reporting
# ----------------------------

def build_report(do_tests: bool, do_logs: bool, timeout: int) -> dict:
    system = get_basic_system_info()
    net = get_network_info(timeout=timeout)

    tests: dict = {}
    if do_tests:
        gw = net.get("gateway") or []
        gw_target = gw[0] if gw else ""
        tests = {
            "ping_gateway": ping(gw_target, count=2, timeout=timeout) if gw_target else {"ok": False, "note": "No gateway detected"},
            "ping_internet_ip": ping("1.1.1.1", count=2, timeout=timeout),
            "dns_lookup_google": dns_lookup("google.com"),
            "http_google": http_test("https://www.google.com", timeout=8),
            "http_cloudflare": http_test("https://1.1.1.1", timeout=8),
        }
    else:
        tests = {"ok": False, "note": "Tests disabled by --no-tests"}

    extras: dict = {
        "top_processes": get_top_processes(limit=10),
    }

    if do_logs and is_windows():
        extras["windows_logs_system"] = windows_recent_errors("System", max_events=25, timeout=timeout)
        extras["windows_logs_application"] = windows_recent_errors("Application", max_events=25, timeout=timeout)
    elif is_windows():
        extras["windows_logs_note"] = "Windows logs disabled by --no-logs"

    # Simple auto-diagnosis (helpdesk-friendly)
    diagnosis = []
    try:
        ping_gw_ok = bool(tests.get("ping_gateway", {}).get("ok"))
        ping_ip_ok = bool(tests.get("ping_internet_ip", {}).get("ok"))
        dns_ok = bool(tests.get("dns_lookup_google", {}).get("ok"))
        http_ok = bool(tests.get("http_google", {}).get("ok") or tests.get("http_cloudflare", {}).get("ok"))
        if do_tests:
            if not ping_gw_ok and net.get("gateway"):
                diagnosis.append("Fallo al hacer ping al gateway: posible problema de red local (Wi-Fi/cable/router).")
            if ping_gw_ok and not ping_ip_ok:
                diagnosis.append("Gateway OK pero no hay salida a Internet por IP: posible caída del ISP o bloqueo/firewall/router.")
            if ping_ip_ok and not dns_ok:
                diagnosis.append("Internet por IP OK pero DNS falla: revisar DNS configurado o servidor DNS.")
            if ping_ip_ok and dns_ok and not http_ok:
                diagnosis.append("Ping y DNS OK pero HTTP falla: posible proxy, firewall, filtrado o problema SSL.")
            if ping_ip_ok and dns_ok and http_ok:
                diagnosis.append("Conectividad básica OK (gateway/IP/DNS/HTTP).")
    except Exception:
        pass

    return {
        "system": system,
        "network": net,
        "tests": tests,
        "extras": extras,
        "diagnosis": diagnosis,
    }


def render_txt(report: dict) -> str:
    sysi = report.get("system", {})
    net = report.get("network", {})
    tests = report.get("tests", {})
    extras = report.get("extras", {})
    diagnosis = report.get("diagnosis", [])

    def line(title: str) -> str:
        return f"\n{'='*10} {title} {'='*10}\n"

    txt: list[str] = []
    txt.append("SOPORTEKIT - INFORME DE DIAGNÓSTICO\n")
    txt.append(f"Fecha: {sysi.get('timestamp')}\n")
    txt.append(f"Host: {sysi.get('hostname')} | Usuario: {sysi.get('user')}\n")

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
            txt.append(f" - {i.get('name')}: {', '.join(i.get('ips', []))}\n")

    txt.append(line("DIAGNÓSTICO RÁPIDO"))
    if diagnosis:
        for d in diagnosis:
            txt.append(f"- {d}\n")
    else:
        txt.append("Sin diagnóstico automático (tests desactivados o insuficientes).\n")

    txt.append(line("TESTS"))
    if isinstance(tests, dict) and tests.get("ok") is False and "note" in tests:
        txt.append(f"{tests.get('note')}\n")
    else:
        for k, v in tests.items():
            if not isinstance(v, dict):
                continue
            ok = v.get("ok")
            txt.append(f"[{k}] OK={ok}\n")
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
    if isinstance(tp, dict) and tp.get("ok"):
        txt.append("Top CPU:\n")
        for p in tp.get("top_cpu", []):
            txt.append(f" - {p.get('name')} (PID {p.get('pid')}): CPU {p.get('cpu_percent')}% | RAM {p.get('ram_rss_gb')} GB\n")
        txt.append("Top RAM:\n")
        for p in tp.get("top_ram", []):
            txt.append(f" - {p.get('name')} (PID {p.get('pid')}): RAM {p.get('ram_rss_gb')} GB | CPU {p.get('cpu_percent')}%\n")
    else:
        txt.append(f"Top procesos: {tp.get('note', 'N/A')}\n")

    if is_windows():
        if "windows_logs_note" in extras:
            txt.append(f"\nWindows logs: {extras['windows_logs_note']}\n")
        else:
            for key in ("windows_logs_system", "windows_logs_application"):
                log = extras.get(key, {})
                txt.append(f"\n{key} OK={log.get('ok')}\n")
                if log.get("note"):
                    txt.append(f"  note: {log.get('note')}\n")
                if log.get("output"):
                    txt.append("  output (recortado):\n")
                    txt.append(textwrap.indent(log["output"][:3000], "    "))
                    txt.append("\n")

    return safe_text("".join(txt))


# ----------------------------
# Main
# ----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SoporteKit - Diagnóstico rápido (TXT + JSON)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--out", default="soportekit_reports", help="Carpeta de salida (default: soportekit_reports)")
    parser.add_argument("--open", action="store_true", help="Abrir la carpeta de salida al final (Windows)")
    parser.add_argument("--no-logs", action="store_true", help="No consultar logs de Windows (más rápido / menos ruido)")
    parser.add_argument("--no-tests", action="store_true", help="No ejecutar tests de red (ping/dns/http)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout comandos (segundos). Default 15")
    args = parser.parse_args()

    base = Path(args.out).expanduser().resolve()
    folder = base / f"report_{now_stamp()}"
    safe_mkdir(folder)

    report = build_report(
        do_tests=not args.no_tests,
        do_logs=not args.no_logs,
        timeout=max(5, int(args.timeout)),
    )

    # Save JSON (UTF-8)
    json_path = folder / "report.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Save TXT (UTF-8)
    txt_path = folder / "report.txt"
    txt_path.write_text(render_txt(report), encoding="utf-8")

    print(f"[OK] Report generado en:\n - {txt_path}\n - {json_path}")

    if args.open and is_windows():
        try:
            os.startfile(str(folder))  # type: ignore[attr-defined]
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
