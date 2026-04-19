import os
import subprocess
import logging
import glob
import time
from pathlib import Path

log = logging.getLogger(__name__)

TAG           = ".rootwatch_sim"
HIDDEN_PREFIX = "rootwatch_hidden_"
PRELOAD_SO    = "/tmp/rootwatch_preload.so"
CRON_MARKER   = "rootwatch_persistence"


def detect_ldpreload():
    result = {"check": "ld_preload_injection", "status": "clean", "findings": [], "confidence": 0}

    if os.path.exists("/etc/ld.so.preload"):
        try:
            content = open("/etc/ld.so.preload").read().strip()
            if content:
                result["findings"].append(f"/etc/ld.so.preload contains: {content}")
                result["confidence"] += 40
        except Exception as e:
            result["findings"].append(f"could not read /etc/ld.so.preload: {e}")

    for path in glob.glob("/tmp/*.so"):
        result["findings"].append(f"suspicious shared object in /tmp: {path}")
        result["confidence"] += 30

    if os.environ.get("LD_PRELOAD"):
        result["findings"].append(f"LD_PRELOAD set: {os.environ['LD_PRELOAD']}")
        result["confidence"] += 20

    for maps_path in glob.glob("/proc/[0-9]*/maps"):
        try:
            maps = open(maps_path).read()
            if "/tmp/" in maps and ".so" in maps:
                pid = maps_path.split("/")[2]
                result["findings"].append(f"PID {pid} has /tmp/*.so in memory maps")
                result["confidence"] += 25
                break
        except Exception:
            continue

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_hidden_processes():
    result = {"check": "hidden_processes", "status": "clean", "findings": [], "confidence": 0}

    try:
        proc_pids = set(int(e) for e in os.listdir("/proc") if e.isdigit())

        ps = subprocess.run(["ps", "-e", "-o", "pid="], capture_output=True, text=True)
        ps_pids = set()
        for line in ps.stdout.strip().splitlines():
            try:
                ps_pids.add(int(line.strip()))
            except ValueError:
                continue

        hidden = proc_pids - ps_pids
        if hidden:
            result["findings"].append(f"PIDs in /proc but not in ps: {sorted(hidden)[:10]}")
            result["confidence"] += 60

        for pid in proc_pids:
            try:
                comm = Path(f"/proc/{pid}/comm").read_text().strip()
                if any(x in comm.lower() for x in ["rootkit", "backdoor", "ghost"]):
                    result["findings"].append(f"suspicious process name: {comm} (PID {pid})")
                    result["confidence"] += 30
            except Exception:
                continue

    except Exception as e:
        result["findings"].append(f"process scan error: {e}")

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_hidden_files():
    result = {"check": "hidden_files", "status": "clean", "findings": [], "confidence": 0}

    try:
        hidden_found = glob.glob(f"/tmp/{HIDDEN_PREFIX}*")
        if hidden_found:
            result["findings"].append(f"hidden payload files found: {[os.path.basename(f) for f in hidden_found]}")
            result["confidence"] += 40

        sim_files = glob.glob(f"/tmp/{TAG}*")
        if sim_files:
            result["findings"].append(f"simulation artifacts present: {[os.path.basename(f) for f in sim_files]}")
            result["confidence"] += 30

    except Exception as e:
        result["findings"].append(f"file scan error: {e}")

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_suid_binaries():
    result = {"check": "suid_binaries", "status": "clean", "findings": [], "confidence": 0}

    known_suid = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/bin/su", "/usr/bin/su", "/usr/bin/pkexec",
    }

    try:
        r = subprocess.run(
            ["find", "/tmp", "/usr/local", "/var/tmp", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.strip().splitlines():
            path = line.strip()
            if path and path not in known_suid:
                result["findings"].append(f"unexpected SUID binary: {path}")
                result["confidence"] += 50

        if os.path.exists("/tmp/rootwatch_suid_shell"):
            result["findings"].append("simulated SUID shell found: /tmp/rootwatch_suid_shell")
            result["confidence"] += 40

    except subprocess.TimeoutExpired:
        result["findings"].append("SUID scan timed out")
    except Exception as e:
        result["findings"].append(f"SUID scan error: {e}")

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_persistence():
    result = {"check": "persistence_vectors", "status": "clean", "findings": [], "confidence": 0}

    for d in ["/var/spool/cron/crontabs", "/etc/cron.d"]:
        if os.path.exists(d):
            for f in os.listdir(d):
                try:
                    content = open(os.path.join(d, f)).read()
                    if CRON_MARKER in content:
                        result["findings"].append(f"rootwatch cron marker in {d}/{f}")
                        result["confidence"] += 40
                except Exception:
                    continue

    sim_cron = f"/tmp/{TAG}_crontab"
    if os.path.exists(sim_cron):
        result["findings"].append(f"simulated cron artifact: {sim_cron}")
        result["confidence"] += 30

    if os.path.exists("/tmp/rootwatch_backdoor.service"):
        result["findings"].append("suspicious systemd unit: /tmp/rootwatch_backdoor.service")
        result["confidence"] += 40

    bashrc_sim = f"/tmp/{TAG}_bashrc"
    if os.path.exists(bashrc_sim):
        content = open(bashrc_sim).read()
        if "LD_PRELOAD" in content:
            result["findings"].append(f"LD_PRELOAD export in simulated .bashrc")
            result["confidence"] += 35

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_library_injection():
    result = {"check": "library_injection", "status": "clean", "findings": [], "confidence": 0}

    for maps_path in glob.glob("/proc/[0-9]*/maps"):
        try:
            pid  = maps_path.split("/")[2]
            maps = open(maps_path).read()
            hits = [l for l in maps.splitlines() if ("/tmp/" in l or "/var/tmp/" in l) and ".so" in l]
            if hits:
                lib = hits[0].split()[-1]
                result["findings"].append(f"PID {pid}: library loaded from {lib}")
                result["confidence"] += 35
        except Exception:
            continue

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_log_tampering():
    result = {"check": "log_tampering", "status": "clean", "findings": [], "confidence": 0}

    for lf in ["/var/log/auth.log", "/var/log/syslog"]:
        if not os.path.exists(lf):
            continue
        try:
            s = os.stat(lf)
            if s.st_size == 0:
                result["findings"].append(f"{lf} is empty — possible truncation")
                result["confidence"] += 40
            if time.time() - s.st_mtime > 86400 * 7:
                result["findings"].append(f"{lf} not modified in over 7 days")
                result["confidence"] += 20
        except Exception:
            continue

    sim_log = f"/tmp/{TAG}_auth.log"
    if os.path.exists(sim_log):
        result["findings"].append(f"simulated tampered log: {sim_log}")
        result["confidence"] += 30

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def detect_network_hiding():
    result = {"check": "network_hiding", "status": "clean", "findings": [], "confidence": 0}

    try:
        ss = subprocess.run(["ss", "-tnp"], capture_output=True, text=True)
        ss_ports = set()
        for line in ss.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and ":" in parts[3]:
                try:
                    ss_ports.add(int(parts[3].split(":")[-1]))
                except ValueError:
                    continue

        proc_ports = set()
        for tcp_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            if os.path.exists(tcp_file):
                for line in open(tcp_file).readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "01":
                        try:
                            proc_ports.add(int(parts[1].split(":")[1], 16))
                        except Exception:
                            continue

        hidden = proc_ports - ss_ports
        if hidden:
            result["findings"].append(f"ports in /proc/net/tcp not visible in ss: {sorted(hidden)[:5]}")
            result["confidence"] += 50

        if os.path.exists(f"/tmp/{TAG}_netstat"):
            result["findings"].append("network hiding simulation marker found")
            result["confidence"] += 20

    except Exception as e:
        result["findings"].append(f"network scan error: {e}")

    result["confidence"] = min(result["confidence"], 100)
    if result["findings"]:
        result["status"] = "detected"
    return result


def run_all():
    checks = [
        detect_ldpreload,
        detect_hidden_processes,
        detect_hidden_files,
        detect_suid_binaries,
        detect_persistence,
        detect_library_injection,
        detect_log_tampering,
        detect_network_hiding,
    ]
    results = []
    for check in checks:
        try:
            results.append(check())
        except Exception as e:
            results.append({"check": check.__name__, "status": "error", "error": str(e), "findings": [], "confidence": 0})
    return results
