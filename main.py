import argparse
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

ROOT = Path(__file__).parent


def main():
    p = argparse.ArgumentParser(description="RootWatch — Linux Rootkit Simulation and Detection Framework")
    p.add_argument("--scan",     action="store_true", help="run headless detection scan")
    p.add_argument("--simulate", metavar="TECHNIQUE",  help="run a specific simulation")
    p.add_argument("--cleanup",  action="store_true", help="remove all simulation artifacts")
    args = p.parse_args()

    if args.cleanup:
        from simulator.techniques import cleanup
        removed = cleanup()
        print(f"removed {len(removed)} artifacts")
        for r in removed:
            print(f"  {r}")
        return

    if args.scan:
        from detector.engine import run_all
        from alerts.logger import write_alert
        results = run_all()
        for r in results:
            status = r.get("status", "clean")
            check  = r.get("check", "")
            conf   = r.get("confidence", 0)
            finds  = r.get("findings", [])
            print(f"\n[{status.upper()}] {check} — confidence: {conf}%")
            for f in finds:
                print(f"  {f}")
            if finds:
                write_alert(check=check, status=status, confidence=conf, findings=finds)
        return

    if args.simulate:
        from simulator.techniques import TECHNIQUES
        if args.simulate not in TECHNIQUES:
            print(f"unknown technique: {args.simulate}")
            print(f"available: {', '.join(TECHNIQUES.keys())}")
            return
        result = TECHNIQUES[args.simulate]()
        print(f"status: {result.get('status')}")
        print(f"detail: {result.get('detail', '')}")
        for a in result.get("artifacts", []):
            print(f"  artifact: {a}")
        return

    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        str(ROOT / "dashboard" / "app.py"),
        "--server.headless", "true",
    ])


if __name__ == "__main__":
    main()
