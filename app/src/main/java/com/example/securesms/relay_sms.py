import subprocess
import threading
import re
import time
import sys

# === CONFIGURATION ===
# If 'adb' is not in your PATH, set the absolute path here.
# Example: ADB_PATH = "C:\\Users\\Georg\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe"
ADB_PATH = "adb" 

def get_connected_devices():
    """Finds all connected emulators (e.g., emulator-5554, emulator-5556)"""
    try:
        result = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines():
            if "emulator" in line and "device" in line:
                parts = line.split()
                devices.append(parts[0])
        return devices
    except FileNotFoundError:
        print("ERROR: 'adb' not found. Check your PATH or set ADB_PATH variable.")
        sys.exit(1)

def monitor_device(serial):
    """Listens to logs from ONE specific device"""
    print(f"[*] Attached listener to {serial}")
    
    cmd = [ADB_PATH, "-s", serial, "logcat", "-v", "raw", "-s", "SecureSMS_Manual"]
    
    # Start logcat process for this specific device
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')

    while True:
        line = process.stdout.readline()
        if not line:
            break # Device disconnected or logcat died
        
        # Look for the specific ADB command we printed in the app
        if "adb -s emulator" in line and "emu sms send" in line:
            clean_cmd = line.strip()
            
            # Extract the command using Regex to ensure safety
            match = re.search(r'(adb -s emulator-\d+ emu sms send \d+ ".*")', clean_cmd)
            
            if match:
                run_cmd = match.group(1)
                    
                # FIX: Redirect replies from "1234" back to the original sender "5554"
                if "emulator-1234" in run_cmd:
                    print("[AUTO-FIX] Redirecting reply to emulator-5554...")
                    run_cmd = run_cmd.replace("emulator-1234", "emulator-5554")

                # If the command uses just 'adb', ensure we use our ADB_PATH
                if ADB_PATH != "adb" and run_cmd.startswith("adb"):
                    run_cmd = run_cmd.replace("adb", f'"{ADB_PATH}"', 1)
                    
                print(f"\n[RELAYING from {serial}] >> {run_cmd}")
                subprocess.run(run_cmd, shell=True)

def main():
    print("=== SECURE SMS MULTI-RELAY TOWER ===")
    
    devices = get_connected_devices()
    
    if not devices:
        print("No emulators found! Make sure they are running.")
        return

    print(f"Found {len(devices)} devices: {', '.join(devices)}")
    print("Starting listeners... (Press Ctrl+C to stop)")
    print("--------------------------------------------")

    threads = []
    for device in devices:
        t = threading.Thread(target=monitor_device, args=(device,))
        t.daemon = True # Ensures threads die when main script dies
        t.start()
        threads.append(t)

    try:
        # Keep the main thread alive so background listeners can run
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTower shutting down.")

if __name__ == "__main__":
    main()