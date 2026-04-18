import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_demo():
    print("=============================================")
    print("  DEMO 6: SBOM Dependency CVE Detection")
    print("=============================================\n")
    
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_process = subprocess.Popen([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    time.sleep(5) 

    try:
        env_attack = env.copy()
        env_attack["FORCE_CVE"] = "true"
        env_attack["SKIP_BAD_BATTERY"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)
    finally:
        server_process.terminate()

if __name__ == "__main__":
    run_demo()
