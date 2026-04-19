TECHNIQUES = {
    "ldpreload": {
        "id":          "T1574.006",
        "name":        "Dynamic Linker Hijacking",
        "tactic":      "Defense Evasion / Persistence",
        "severity":    "critical",
        "description": "Adversaries inject malicious shared libraries via LD_PRELOAD or /etc/ld.so.preload to hook libc functions and manipulate system call output. Used by Symbiote, Orbit, HiddenWasp, and PUMAKIT.",
        "references":  ["Wiz Research 2023", "Elastic Security PUMAKIT 2024"],
        "mitigations": [
            "Monitor /etc/ld.so.preload for unauthorised modifications",
            "Use statically linked tools for forensic analysis",
            "Restrict LD_PRELOAD via PAM limits for non-root users",
        ],
    },
    "process": {
        "id":          "T1014",
        "name":        "Rootkit — Process Hiding",
        "tactic":      "Defense Evasion",
        "severity":    "critical",
        "description": "Rootkits intercept /proc filesystem traversal via readdir() hooks to remove their processes from ps, top, and htop output while maintaining a valid /proc/PID directory.",
        "references":  ["MITRE ATT&CK T1014"],
        "mitigations": [
            "Cross-reference /proc PID list against ps output",
            "Use kernel-level tools that bypass userspace hooks",
        ],
    },
    "files": {
        "id":          "T1564.001",
        "name":        "Hidden Files and Directories",
        "tactic":      "Defense Evasion",
        "severity":    "high",
        "description": "Malicious files are hidden from directory listing commands by hooking readdir() and getdents() to filter specific filenames from output.",
        "references":  ["MITRE ATT&CK T1564.001"],
        "mitigations": [
            "Use direct inode scanning rather than readdir() for enumeration",
            "Deploy file integrity monitoring using kernel-level hooks",
        ],
    },
    "suid": {
        "id":          "T1548.001",
        "name":        "Setuid and Setgid",
        "tactic":      "Privilege Escalation / Defense Evasion",
        "severity":    "critical",
        "description": "Attackers plant SUID binaries that execute with root privileges regardless of the calling user. Combined with process hiding these backdoors are difficult to detect.",
        "references":  ["MITRE ATT&CK T1548.001"],
        "mitigations": [
            "Audit SUID binaries regularly using find -perm -4000",
            "Mount sensitive filesystems with nosuid flag",
        ],
    },
    "persistence": {
        "id":          "T1053.003",
        "name":        "Cron / Scheduled Task Persistence",
        "tactic":      "Persistence",
        "severity":    "high",
        "description": "Multiple persistence vectors deployed simultaneously — cron jobs, systemd units, .bashrc injection — ensuring the rootkit survives reboots and user account changes.",
        "references":  ["MITRE ATT&CK T1053.003"],
        "mitigations": [
            "Audit cron directories and systemd unit files regularly",
            "Monitor .bashrc and profile files for LD_PRELOAD exports",
        ],
    },
    "logs": {
        "id":          "T1070.002",
        "name":        "Indicator Removal — Syslog",
        "tactic":      "Defense Evasion",
        "severity":    "high",
        "description": "Rootkits intercept write() calls to log files or directly edit them to remove evidence of attacker activity including IP addresses and authentication events.",
        "references":  ["MITRE ATT&CK T1070.002"],
        "mitigations": [
            "Forward logs to a remote syslog server in real time",
            "Implement write-once log storage",
        ],
    },
    "network": {
        "id":          "T1014",
        "name":        "Rootkit — Network Connection Hiding",
        "tactic":      "Defense Evasion / Command and Control",
        "severity":    "critical",
        "description": "C2 connections are hidden from netstat and ss by filtering /proc/net/tcp entries via hooked read() calls. The connection remains active but invisible to standard network monitoring.",
        "references":  ["Sandfly Security 2024"],
        "mitigations": [
            "Cross-reference /proc/net/tcp directly against ss output",
            "Deploy network monitoring at the hypervisor level",
        ],
    },
    "timestamps": {
        "id":          "T1070.006",
        "name":        "Timestomping",
        "tactic":      "Defense Evasion",
        "severity":    "medium",
        "description": "Malicious files have their timestamps backdated to match legitimate system files, evading timeline-based forensic analysis and file integrity monitoring.",
        "references":  ["MITRE ATT&CK T1070.006"],
        "mitigations": [
            "Use cryptographic hashing rather than timestamps for integrity checking",
            "Compare inode change time (ctime) which cannot be backdated without root",
        ],
    },
}

TACTIC_GROUPS = {
    "Defense Evasion":       ["ldpreload", "process", "files", "logs", "network", "timestamps"],
    "Persistence":           ["persistence"],
    "Privilege Escalation":  ["suid"],
    "Command and Control":   ["network"],
}


def get_tactic_summary():
    return {tactic: len(keys) for tactic, keys in TACTIC_GROUPS.items()}


def get_all():
    return TECHNIQUES
