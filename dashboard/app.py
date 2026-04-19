import json
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from simulator.techniques import TECHNIQUES as SIM_TECHNIQUES, cleanup
from detector.engine import run_all
from mitre.mapper import TECHNIQUES as MITRE_TECHNIQUES, get_tactic_summary
from alerts.logger import write_alert, load_alerts, clear_alerts

st.set_page_config(
    page_title="RootWatch",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🔍"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
    background-color: #060810 !important;
    color: #e2e8f0 !important;
    font-size: 15px !important;
}
.stApp { background-color: #060810 !important; }

section[data-testid="stSidebar"] {
    background-color: #080b14 !important;
    border-right: 1px solid #1a2035 !important;
}
section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }

.stTabs [data-baseweb="tab-list"] {
    background-color: #0d1120 !important;
    border-radius: 12px !important;
    padding: 5px !important;
    gap: 4px !important;
    border-bottom: none !important;
}
.stTabs [data-baseweb="tab"] {
    background-color: transparent !important;
    border-radius: 8px !important;
    color: #4a5568 !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    padding: 10px 22px !important;
    border: none !important;
}
.stTabs [aria-selected="true"] {
    background: #ef4444 !important;
    color: #fff !important;
    font-weight: 700 !important;
    border-radius: 30px !important;
}
.stTabs [data-baseweb="tab-highlight"] { display: none !important; }
.stTabs [data-baseweb="tab-border"]    { display: none !important; }

div[data-testid="metric-container"] {
    background-color: #0d1120 !important;
    border-radius: 14px !important;
    padding: 22px 24px !important;
    border: 1px solid #1a2035 !important;
}
div[data-testid="metric-container"] label {
    font-size: 13px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.8px !important;
    color: #64748b !important;
    font-weight: 700 !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-size: 34px !important;
    font-weight: 800 !important;
    color: #ffffff !important;
    font-family: 'JetBrains Mono', monospace !important;
}

.stButton > button {
    border-radius: 10px !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    padding: 12px 24px !important;
    width: 100% !important;
    border: none !important;
}

.stDataFrame { background: #0d1120 !important; border-radius: 10px !important; }
.stDataFrame * { color: #e2e8f0 !important; font-size: 14px !important; }

div[data-testid="stExpander"] {
    background: #0d1120 !important;
    border-radius: 10px !important;
    border: 1px solid #1a2035 !important;
}
div[data-testid="stExpander"] summary { font-size: 15px !important; color: #e2e8f0 !important; font-weight: 600 !important; }

h1, h2, h3, h4 { color: #ffffff !important; font-weight: 800 !important; }
p, li { color: #e2e8f0 !important; font-size: 15px !important; }

.panel {
    background: #0d1120;
    border: 1px solid #1a2035;
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 16px;
}
.panel-title {
    font-size: 13px;
    font-weight: 700;
    color: #ef4444;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 16px;
}
.technique-card {
    background: #0a0e1a;
    border: 1px solid #1a2035;
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 10px;
    transition: border-color 0.2s;
}
.technique-card:hover { border-color: #ef4444; }
.technique-card .tc-name { font-size: 16px; font-weight: 700; color: #ffffff; margin-bottom: 6px; }
.technique-card .tc-id   { font-size: 12px; color: #ef4444; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px; }
.technique-card .tc-desc { font-size: 14px; color: #94a3b8; line-height: 1.6; }
.finding-item {
    background: #12011a;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 8px;
    font-size: 14px;
    color: #fca5a5;
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all;
}
.clean-item {
    background: #011a0a;
    border-left: 4px solid #22c55e;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 8px;
    font-size: 14px;
    color: #86efac;
}
.sim-card {
    background: #0a0e1a;
    border: 1px solid #1a2035;
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 10px;
}
.sim-card .sc-name { font-size: 15px; font-weight: 700; color: #ffffff; margin-bottom: 4px; }
.sim-card .sc-id   { font-size: 12px; color: #ef4444; font-family: 'JetBrains Mono', monospace; }
.badge-critical { background: rgba(239,68,68,0.2);  color: #ef4444;  font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; border: 1px solid #ef4444; }
.badge-high     { background: rgba(249,115,22,0.2); color: #f97316;  font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; border: 1px solid #f97316; }
.badge-medium   { background: rgba(234,179,8,0.2);  color: #eab308;  font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; border: 1px solid #eab308; }
.badge-detected { background: rgba(239,68,68,0.2);  color: #ef4444;  font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; }
.badge-clean    { background: rgba(34,197,94,0.2);  color: #22c55e;  font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; }
.main .block-container { max-width: 100% !important; padding-left: 2.5rem !important; padding-right: 2.5rem !important; padding-top: 2rem !important; }
hr { border-color: #1a2035 !important; }
</style>
""", unsafe_allow_html=True)


def dark_chart(fig):
    fig.update_layout(
        paper_bgcolor="#0d1120",
        plot_bgcolor="#0d1120",
        font_color="#e2e8f0",
        font_family="Inter",
        margin=dict(l=10, r=10, t=36, b=10),
        legend=dict(bgcolor="#0d1120"),
    )
    fig.update_xaxes(gridcolor="#1a2035", zerolinecolor="#1a2035")
    fig.update_yaxes(gridcolor="#1a2035", zerolinecolor="#1a2035")
    return fig


def severity_badge(sev):
    return f'<span class="badge-{sev}">{sev.upper()}</span>'


def status_badge(status):
    cls = "badge-detected" if status == "detected" else "badge-clean"
    return f'<span class="{cls}">{status.upper()}</span>'


if "sim_results" not in st.session_state:
    st.session_state.sim_results = {}
if "det_results" not in st.session_state:
    st.session_state.det_results = []


with st.sidebar:
    st.markdown("""
    <div style="padding-bottom:18px;border-bottom:1px solid #1a2035;margin-bottom:16px;">
      <div style="font-size:22px;font-weight:800;color:#fff;font-family:'JetBrains Mono',monospace;">Root<span style="color:#ef4444">Watch</span></div>
      <div style="font-size:11px;color:#4a5568;text-transform:uppercase;letter-spacing:1.2px;margin-top:4px;">Linux Rootkit Framework</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:10px;font-weight:700;">System Status</div>', unsafe_allow_html=True)

    alerts = load_alerts()
    detected_count = len([a for a in alerts if a.get("status") == "detected"])
    sim_count      = len(st.session_state.sim_results)

    st.markdown(f"""
    <div style="background:#0d1120;border:1px solid #1a2035;border-radius:10px;padding:14px 16px;margin-bottom:8px;">
      <div style="display:flex;justify-content:space-between;font-size:14px;margin-bottom:6px;">
        <span style="color:#64748b;font-weight:600;">Active Detections</span>
        <span style="color:{'#ef4444' if detected_count > 0 else '#22c55e'};font-weight:700;font-family:'JetBrains Mono',monospace;">{detected_count}</span>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:14px;">
        <span style="color:#64748b;font-weight:600;">Simulations Run</span>
        <span style="color:#e2e8f0;font-weight:700;font-family:'JetBrains Mono',monospace;">{sim_count}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Run Full Detection Scan", key="sidebar_scan"):
        with st.spinner("Scanning system..."):
            results = run_all()
            st.session_state.det_results = results
            for r in results:
                if r.get("findings"):
                    mitre_key = r.get("check","").replace("detect_","").split("_")[0]
                    t = MITRE_TECHNIQUES.get(mitre_key, {})
                    write_alert(
                        check=r["check"],
                        status=r["status"],
                        confidence=r.get("confidence",0),
                        findings=r.get("findings",[]),
                        technique_id=t.get("id"),
                    )
        st.success("Scan complete")

    if st.button("Clear All Alerts", key="sidebar_clear"):
        clear_alerts()
        st.session_state.det_results = []
        st.session_state.sim_results = {}
        st.rerun()

    if st.button("Cleanup Simulation Artifacts", key="sidebar_cleanup"):
        removed = cleanup()
        st.success(f"Removed {len(removed)} artifacts")

    st.markdown("""
    <div style="margin-top:32px;font-size:11px;color:#1e293b;text-transform:uppercase;letter-spacing:0.8px;">
    RootWatch v1.0 — Kali Linux
    </div>
    """, unsafe_allow_html=True)


st.markdown(f"""
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:28px;">
  <div>
    <h2 style="margin:0;font-size:26px;font-weight:800;color:#fff;">RootWatch</h2>
    <p style="color:#4a5568;font-size:14px;margin-top:4px;font-weight:500;">Linux Rootkit Simulation and Detection Framework — {datetime.now().strftime('%d %b %Y %H:%M')}</p>
  </div>
  <div style="background:#0d1120;border:1px solid #1a2035;border-radius:20px;padding:8px 16px;font-size:12px;color:#ef4444;font-weight:700;letter-spacing:0.5px;">
    {'⚠ DETECTIONS ACTIVE' if detected_count > 0 else '✓ SYSTEM CLEAN'}
  </div>
</div>
""", unsafe_allow_html=True)

alerts = load_alerts()
det_results = st.session_state.det_results

total_checks   = len(det_results) if det_results else 8
detected       = len([r for r in det_results if r.get("status") == "detected"])
clean          = len([r for r in det_results if r.get("status") == "clean"])
avg_confidence = int(sum(r.get("confidence",0) for r in det_results) / len(det_results)) if det_results else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Checks Run",        total_checks)
c2.metric("Detections",        detected)
c3.metric("Clean",             clean)
c4.metric("Avg Confidence",    f"{avg_confidence}%")

st.markdown("<br>", unsafe_allow_html=True)

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Simulation Control", "Live Detection", "MITRE ATT&CK", "Timeline", "Forensic Report"
])


with tab1:
    st.markdown('<div class="panel-title">Rootkit Technique Simulator</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:#64748b;font-size:14px;margin-bottom:24px;">Each module simulates a real rootkit technique used in the wild. All artifacts are confined to /tmp and can be cleaned up at any time.</p>', unsafe_allow_html=True)

    technique_meta = {
        "ldpreload":   ("T1574.006", "LD_PRELOAD Injection",       "critical", "Compiles a shared object that hooks readdir() and fopen() to hide files and conceal /etc/ld.so.preload. Based on Symbiote, PUMAKIT, and Medusa techniques."),
        "process":     ("T1014",     "Process Hiding",              "critical", "Spawns a background process that would be unlinked from /proc traversal in a real rootkit, making it invisible to ps and top."),
        "files":       ("T1564.001", "File Hiding",                 "high",     "Creates payload files prefixed to be filtered by the LD_PRELOAD readdir hook. Simulates how rootkits hide their tooling on disk."),
        "suid":        ("T1548.001", "SUID Backdoor Implant",       "critical", "Drops a shell script to /tmp that would be compiled and chmod u+s in a real attack to give unprivileged users a root shell."),
        "persistence": ("T1053.003", "Multi-Vector Persistence",    "high",     "Installs three persistence vectors simultaneously — cron, systemd unit, and .bashrc LD_PRELOAD export — ensuring survival across reboots."),
        "logs":        ("T1070.002", "Log Tampering",               "high",     "Simulates selective auth.log modification, removing attacker IP addresses and SSH authentication events from the log file."),
        "network":     ("T1014",     "Network Connection Hiding",   "critical", "Demonstrates how rootkits filter /proc/net/tcp entries to conceal C2 connections from netstat, ss, and lsof."),
        "timestamps":  ("T1070.006", "Timestamp Manipulation",      "medium",   "Backdates a file to 2020 using touch -t to evade timeline-based forensic analysis and file integrity monitoring."),
    }

    col_left, col_right = st.columns(2)

    for i, (key, (tid, name, severity, desc)) in enumerate(technique_meta.items()):
        col = col_left if i % 2 == 0 else col_right
        with col:
            sim_result = st.session_state.sim_results.get(key, {})
            status_color = "#22c55e" if sim_result.get("status") == "ok" else "#ef4444" if sim_result.get("status") == "error" else "#1a2035"

            st.markdown(f"""
            <div class="sim-card" style="border-color:{status_color}33;">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                <div>
                  <div class="sc-name">{name}</div>
                  <div class="sc-id">{tid}</div>
                </div>
                {severity_badge(severity)}
              </div>
              <div style="font-size:13px;color:#64748b;line-height:1.6;margin-bottom:12px;">{desc}</div>
              {'<div style="font-size:12px;color:#22c55e;font-family:JetBrains Mono,monospace;margin-top:4px;">✓ Executed — ' + str(len(sim_result.get("artifacts",[]))) + ' artifact(s)</div>' if sim_result.get("status") == "ok" else ''}
              {'<div style="font-size:12px;color:#ef4444;margin-top:4px;">✗ ' + sim_result.get("error","Error")[:60] + '</div>' if sim_result.get("status") == "error" else ''}
            </div>
            """, unsafe_allow_html=True)

            btn_label = "Re-run" if sim_result else "Execute"
            if st.button(f"{btn_label}: {name}", key=f"sim_{key}"):
                from simulator.techniques import TECHNIQUES as T
                with st.spinner(f"Simulating {name}..."):
                    try:
                        result = T[key]()
                        st.session_state.sim_results[key] = result
                    except Exception as e:
                        st.session_state.sim_results[key] = {"status": "error", "error": str(e), "artifacts": []}
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Execute All Techniques", key="run_all_sim"):
            from simulator.techniques import TECHNIQUES as T
            with st.spinner("Running all simulations..."):
                for key, fn in T.items():
                    try:
                        st.session_state.sim_results[key] = fn()
                    except Exception as e:
                        st.session_state.sim_results[key] = {"status": "error", "error": str(e), "artifacts": []}
            st.success("All simulations complete. Run detection scan to see results.")
            st.rerun()


with tab2:
    st.markdown('<div class="panel-title">Live Detection Engine</div>', unsafe_allow_html=True)

    if not det_results:
        st.markdown('<div style="color:#4a5568;font-size:15px;padding:20px 0;">No scan results yet. Click "Run Full Detection Scan" in the sidebar.</div>', unsafe_allow_html=True)
    else:
        check_labels = {
            "ld_preload_injection":   "LD_PRELOAD Injection",
            "hidden_processes":       "Hidden Processes",
            "hidden_files":           "Hidden Files",
            "suid_binaries":          "SUID Binaries",
            "persistence_vectors":    "Persistence Vectors",
            "library_injection":      "Library Injection",
            "log_tampering":          "Log Tampering",
            "network_hiding":         "Network Hiding",
        }

        for result in det_results:
            check_name = check_labels.get(result.get("check",""), result.get("check",""))
            status     = result.get("status", "clean")
            confidence = result.get("confidence", 0)
            findings   = result.get("findings", [])

            icon  = "⚠" if status == "detected" else "✓"
            color = "#ef4444" if status == "detected" else "#22c55e"

            with st.expander(f"{icon}  {check_name}  —  Confidence: {confidence}%"):
                col1, col2 = st.columns([2,1])
                with col1:
                    st.markdown(f'<div style="font-size:15px;font-weight:700;color:{color};margin-bottom:12px;">{status.upper()}</div>', unsafe_allow_html=True)
                    if findings:
                        for f in findings:
                            st.markdown(f'<div class="finding-item">{f}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="clean-item">No indicators detected for this check.</div>', unsafe_allow_html=True)
                with col2:
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=confidence,
                        gauge={
                            "axis": {"range": [0, 100]},
                            "bar":  {"color": "#ef4444" if confidence > 50 else "#eab308" if confidence > 20 else "#22c55e"},
                            "steps": [
                                {"range": [0,30],   "color": "#0d1120"},
                                {"range": [30,60],  "color": "#0d1120"},
                                {"range": [60,100], "color": "#0d1120"},
                            ],
                            "bgcolor": "#0d1120",
                        },
                        number={"suffix": "%", "font": {"color": "#fff", "size": 28}},
                    ))
                    fig.update_layout(height=180, paper_bgcolor="#0d1120", margin=dict(l=10,r=10,t=10,b=10))
                    st.plotly_chart(fig, use_container_width=True)

        # Summary chart
        st.markdown("<br>", unsafe_allow_html=True)
        df_det = pd.DataFrame([{
            "Check":      check_labels.get(r.get("check",""), r.get("check","")),
            "Confidence": r.get("confidence", 0),
            "Status":     r.get("status", "clean"),
        } for r in det_results])

        fig = px.bar(
            df_det, x="Confidence", y="Check", orientation="h",
            color="Status",
            color_discrete_map={"detected": "#ef4444", "clean": "#22c55e", "error": "#f97316"},
            title="Detection Confidence by Check",
        )
        fig.update_layout(xaxis_range=[0,100], xaxis_title="Confidence %", yaxis_title="")
        st.plotly_chart(dark_chart(fig), use_container_width=True)


with tab3:
    st.markdown('<div class="panel-title">MITRE ATT&CK for Linux — Technique Coverage</div>', unsafe_allow_html=True)

    col_left, col_right = st.columns([1.6, 1])

    with col_left:
        tactic_data = get_tactic_summary()
        fig = px.bar(
            x=list(tactic_data.values()),
            y=list(tactic_data.keys()),
            orientation="h",
            title="Techniques by Tactic",
            color_discrete_sequence=["#ef4444"],
        )
        fig.update_layout(xaxis_title="Technique Count", yaxis_title="")
        st.plotly_chart(dark_chart(fig), use_container_width=True)

        # Heatmap of detected vs simulated
        sim_keys = list(st.session_state.sim_results.keys())
        det_keys = [r.get("check","").replace("detect_","").split("_")[0] for r in det_results if r.get("status")=="detected"]

        heat_data = []
        for key, t in MITRE_TECHNIQUES.items():
            heat_data.append({
                "Technique": f"{t['id']} {t['name'][:25]}",
                "Simulated": 1 if key in sim_keys else 0,
                "Detected":  1 if any(key in dk for dk in det_keys) else 0,
            })

        df_heat = pd.DataFrame(heat_data)
        fig2 = go.Figure(data=go.Heatmap(
            z=df_heat[["Simulated","Detected"]].values.T,
            x=df_heat["Technique"],
            y=["Simulated","Detected"],
            colorscale=[[0,"#0d1120"],[0.5,"#7c1a1a"],[1,"#ef4444"]],
            showscale=False,
        ))
        fig2.update_layout(title="Simulation vs Detection Coverage", height=200)
        st.plotly_chart(dark_chart(fig2), use_container_width=True)

    with col_right:
        st.markdown('<div style="font-size:13px;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;">Technique Details</div>', unsafe_allow_html=True)
        for key, t in MITRE_TECHNIQUES.items():
            with st.expander(f"{t['id']} — {t['name']}"):
                st.markdown(f'<div style="font-size:13px;color:#64748b;margin-bottom:8px;"><b style="color:#ef4444">Tactic:</b> {t["tactic"]}</div>', unsafe_allow_html=True)
                st.markdown(f'<span class="badge-{t["severity"]}">{t["severity"].upper()}</span>', unsafe_allow_html=True)
                st.markdown(f'<div style="font-size:14px;color:#94a3b8;margin:10px 0;line-height:1.6;">{t["description"]}</div>', unsafe_allow_html=True)
                st.markdown('<div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:8px;">Mitigations</div>', unsafe_allow_html=True)
                for m in t["mitigations"]:
                    st.markdown(f'<div style="font-size:13px;color:#64748b;padding:4px 0;border-bottom:1px solid #1a2035;">→ {m}</div>', unsafe_allow_html=True)
                if t.get("references"):
                    st.markdown(f'<div style="font-size:12px;color:#4a5568;margin-top:8px;">References: {", ".join(t["references"])}</div>', unsafe_allow_html=True)


with tab4:
    st.markdown('<div class="panel-title">Attack Timeline</div>', unsafe_allow_html=True)

    if not alerts:
        st.markdown('<div style="color:#4a5568;font-size:15px;padding:20px 0;">No events recorded yet. Run simulations and detection scans to populate the timeline.</div>', unsafe_allow_html=True)
    else:
        df_alerts = pd.DataFrame(alerts)
        df_alerts["timestamp"] = pd.to_datetime(df_alerts["timestamp"])
        df_alerts["time_str"]  = df_alerts["timestamp"].dt.strftime("%H:%M:%S")

        for _, row in df_alerts.sort_values("timestamp", ascending=False).iterrows():
            color = "#ef4444" if row.get("status") == "detected" else "#22c55e"
            conf  = row.get("confidence", 0)
            finds = row.get("findings", [])

            st.markdown(f"""
            <div style="display:flex;gap:16px;margin-bottom:12px;align-items:flex-start;">
              <div style="font-size:12px;color:#4a5568;font-family:'JetBrains Mono',monospace;white-space:nowrap;padding-top:2px;min-width:80px;">{row.get("time_str","")}</div>
              <div style="width:3px;background:{color};border-radius:2px;align-self:stretch;flex-shrink:0;"></div>
              <div style="flex:1;background:#0d1120;border:1px solid #1a2035;border-radius:10px;padding:14px 16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                  <div style="font-size:15px;font-weight:700;color:#fff;">{row.get("check","").replace("_"," ").title()}</div>
                  <div style="display:flex;gap:8px;align-items:center;">
                    <span style="font-size:12px;color:#4a5568;font-family:'JetBrains Mono',monospace;">conf: {conf}%</span>
                    {status_badge(row.get("status","clean"))}
                  </div>
                </div>
                {f'<div style="font-size:12px;color:#64748b;font-family:JetBrains Mono,monospace;">{row.get("technique_id","")}</div>' if row.get("technique_id") else ""}
                {f'<div style="font-size:13px;color:#94a3b8;margin-top:6px;">{finds[0][:120]}{"..." if len(str(finds[0])) > 120 else ""}</div>' if finds else ""}
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        if len(df_alerts) > 1:
            df_alerts["minute"] = df_alerts["timestamp"].dt.floor("min")
            freq = df_alerts.groupby(["minute","status"]).size().reset_index(name="count")
            fig = px.line(freq, x="minute", y="count", color="status",
                color_discrete_map={"detected": "#ef4444", "clean": "#22c55e"},
                title="Alert Frequency Over Time", markers=True)
            st.plotly_chart(dark_chart(fig), use_container_width=True)


with tab5:
    st.markdown('<div class="panel-title">Forensic Report</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div style="background:#0d1120;border:1px solid #1a2035;border-radius:12px;padding:20px 24px;margin-bottom:20px;">
      <div style="font-size:18px;font-weight:800;color:#fff;margin-bottom:14px;font-family:'JetBrains Mono',monospace;">RootWatch Forensic Summary</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">Generated:</span> <span style="color:#e2e8f0;font-family:'JetBrains Mono',monospace;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></div>
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">System:</span> <span style="color:#e2e8f0;font-family:'JetBrains Mono',monospace;">Kali Linux</span></div>
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">Checks Run:</span> <span style="color:#e2e8f0;font-family:'JetBrains Mono',monospace;">{total_checks}</span></div>
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">Detections:</span> <span style="color:{'#ef4444' if detected > 0 else '#22c55e'};font-family:'JetBrains Mono',monospace;font-weight:700;">{detected}</span></div>
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">Simulations:</span> <span style="color:#e2e8f0;font-family:'JetBrains Mono',monospace;">{sim_count}</span></div>
        <div style="font-size:14px;"><span style="color:#4a5568;font-weight:600;">Total Alerts:</span> <span style="color:#e2e8f0;font-family:'JetBrains Mono',monospace;">{len(alerts)}</span></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    if det_results:
        st.markdown('<div style="font-size:13px;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px;">Detection Results</div>', unsafe_allow_html=True)
        det_df = pd.DataFrame([{
            "Check":      r.get("check","").replace("_"," ").title(),
            "Status":     r.get("status","").upper(),
            "Confidence": f"{r.get('confidence',0)}%",
            "Findings":   len(r.get("findings",[])),
        } for r in det_results])
        st.dataframe(det_df, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)

    report_data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "checks_run":    total_checks,
            "detections":    detected,
            "clean":         clean,
            "simulations":   sim_count,
            "total_alerts":  len(alerts),
        },
        "detection_results": det_results,
        "simulation_results": st.session_state.sim_results,
        "alerts": alerts,
    }

    with c1:
        st.download_button(
            "Export JSON Report",
            json.dumps(report_data, indent=2, default=str),
            file_name=f"rootwatch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with c2:
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, "RootWatch - Forensic Report", ln=True)
            pdf.set_font("Helvetica", size=10)
            pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.cell(0, 6, f"Checks Run: {total_checks}  Detections: {detected}  Clean: {clean}", ln=True)
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Detection Results", ln=True)
            pdf.set_font("Helvetica", size=10)
            for r in det_results:
                status = r.get("status","").upper()
                check  = r.get("check","").replace("_"," ").title()
                conf   = r.get("confidence",0)
                pdf.cell(0, 6, f"{check}: {status} (confidence: {conf}%)", ln=True)
                for f in r.get("findings",[])[:3]:
                    safe = str(f)[:90].encode("latin-1", errors="replace").decode("latin-1")
                    pdf.cell(0, 5, f"  - {safe}", ln=True)
            pdf_bytes = pdf.output()
            st.download_button(
                "Export PDF Report",
                bytes(pdf_bytes),
                file_name=f"rootwatch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except ImportError:
            st.info("Install fpdf2 for PDF export: pip install fpdf2")
