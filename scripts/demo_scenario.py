import os
import subprocess
import time
import sys

# Ensure path works dynamically
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_adversarial_demo():
    print("=============================================")
    print(" ADVANCED DEMO SCENARIO (MULTI-MACHINE MOCK) ")
    print("=============================================\n")
    
    # Start Cloud Instance
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_process = subprocess.Popen([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    
    # Let OTA server and fleet dashboard boot and build initial dummy firmware
    time.sleep(5) 

    try:
        print("\n--- SCENARIO 1: NORMAL VEHICLE UPDATE ---")
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env, cwd=root_dir)

        print("\n--- SCENARIO 2: KALI LINUX MITM CHUNK TAMPERING ---")
        print("    [!] Attacker intercepts OTA traffic and flips bytes in chunk payload")
        env_attack1 = env.copy()
        env_attack1["ATTACK_ENABLED"] = "true"
        env_attack1["ATTACK_TARGET"] = "chunk"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack1, cwd=root_dir)

        print("\n--- SCENARIO 3: KALI LINUX MITM MANIFEST INTERCEPTION ---")
        print("    [!] Attacker intercepts manifest. Attempts to downgrade firmware via replay.")
        env_attack2 = env.copy()
        env_attack2["ATTACK_ENABLED"] = "true"
        env_attack2["ATTACK_TARGET"] = "manifest"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack2, cwd=root_dir)

        print("\n[+] Demo SCENARIOS Complete. Check Fleet Dashboard to view blocked and failed logs.")
    finally:
        server_process.terminate()

if __name__ == "__main__":
    run_adversarial_demo()
