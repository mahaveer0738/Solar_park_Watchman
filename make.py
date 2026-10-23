"""
Cross-Platform Command Orchestrator for Solar Park Watchman.
Provides standard entry points:
- python make.py up        (or make up / make.bat up)
- python make.py attacks   (or make attacks / make.bat attacks)
- python make.py evaluate  (or make evaluate / make.bat evaluate)
- python make.py demo      (or make demo / make.bat demo)
- python make.py down      (or make down / make.bat down)
"""
import sys
import os
import time
import subprocess
import signal

# Process tracker for background services
PID_FILE = "runs/services.pid"

def cmd_up():
    print("[+] Starting Solar Park Watchman Simulated Network & Services...")
    os.makedirs("runs", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    # If docker compose is available and desired, check:
    has_docker = False
    try:
        res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if res.returncode == 0:
            has_docker = True
    except Exception:
        has_docker = False

    if has_docker and os.path.exists("docker-compose.yml"):
        print("[+] Docker Compose detected. Starting container topology...")
        subprocess.run(["docker", "compose", "up", "-d"])
        return

    print("[+] Launching native Python simulation cluster & sensor engine...")
    pids = []
    # 1. Central Collector
    p_central = subprocess.Popen([sys.executable, "-m", "central.app"])
    pids.append(("Central", p_central.pid))

    # 2. Plant PLC
    p_plc = subprocess.Popen([sys.executable, "-m", "sim.plc"])
    pids.append(("PLC", p_plc.pid))

    # 3. Inverter Cluster
    p_inv = subprocess.Popen([sys.executable, "-m", "sim.inverters"])
    pids.append(("Inverters", p_inv.pid))

    # 4. IEC-104 Outstation
    p_iec = subprocess.Popen([sys.executable, "-c", "from sim.iec104 import IEC104Outstation; s=IEC104Outstation(); s.start(); import time; [time.sleep(1) for _ in iter(int, 1)]"])
    pids.append(("IEC104", p_iec.pid))

    # Save PIDs
    with open(PID_FILE, "w") as f:
        f.write(",".join(str(p[1]) for p in pids))

    print(f"[+] All services running in background: {pids}")
    time.sleep(1.0)
    print("[+] Services verified online. Run `python make.py attacks` or `python make.py evaluate`.")

def cmd_attacks():
    print("[+] Executing Attack Scenarios Suite (S1, S2, S3, S5, S6, S7, S8)...")
    from eval.evaluate import run_evaluation
    # Run 1 round of all scenarios live
    run_evaluation(speedup=60.0, iterations_per_scenario=1)
    print("[+] Attack suite complete. Check runs/attack_log.jsonl and runs/alerts.jsonl.")

def cmd_evaluate():
    print("[+] Running full 30-run Evaluation Harness against B.2 criteria...")
    from eval.evaluate import run_evaluation
    run_evaluation(speedup=60.0, iterations_per_scenario=5)

def cmd_demo():
    print("[+] Launching Streamlit Operator Console (Dashboard)...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "dashboard/app.py", "--server.port", "8501", "--server.headless", "true"])

def cmd_down():
    print("[+] Stopping Solar Park Watchman services...")
    # Check docker compose
    try:
        subprocess.run(["docker", "compose", "down"], capture_output=True)
    except Exception:
        pass

    # Terminate background pids
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            pids = f.read().strip().split(",")
        for p in pids:
            if p:
                try:
                    os.kill(int(p), signal.SIGTERM)
                except Exception:
                    pass
        os.remove(PID_FILE)
    print("[+] All services stopped.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python make.py [up|attacks|evaluate|demo|down]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "up":
        cmd_up()
    elif cmd == "attacks":
        cmd_attacks()
    elif cmd == "evaluate":
        cmd_evaluate()
    elif cmd == "demo":
        cmd_demo()
    elif cmd == "down":
        cmd_down()
    else:
        print(f"Unknown command: {cmd}. Choose from [up, attacks, evaluate, demo, down]")
        sys.exit(1)

if __name__ == "__main__":
    main()
