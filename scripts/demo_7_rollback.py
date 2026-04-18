import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_demo():
    print("=============================================")
    print("  DEMO 7: Automatic Rollback (Rogue Server)")
    print("=============================================\n")
    print("  Simulates a rogue OTA server with mismatched signing keys.")
    print("  The ECU detects the signature failure and triggers automatic rollback.\n")
    
    env = os.environ.copy()
    env["SKIP_BAD_BATTERY"] = "true"
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_process = subprocess.Popen([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    time.sleep(10) 

    try:
        env_attack = env.copy()
        env_attack["ROGUE_HSM"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)
    finally:
        server_process.terminate()

if __name__ == "__main__":
    run_demo()

