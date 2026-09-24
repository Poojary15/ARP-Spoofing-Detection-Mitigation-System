import subprocess
import sys
import re
import time
import winsound

from scapy.all import ARP, Ether, srp, sniff

# -------------------------------
# GLOBAL STORAGE
# -------------------------------
logged_attackers = set()

last_attack_time = 0
ATTACK_TIMEOUT = 5   # seconds

# -------------------------------
# STEP 1: GET GATEWAY IP
# -------------------------------
def get_gateway():

    try:

        result = subprocess.check_output(
            "ipconfig",
            shell=True
        ).decode()

        lines = result.split("\n")

        for i in range(len(lines)):

            if "Default Gateway" in lines[i]:

                # Check same line
                parts = lines[i].split(":")

                if len(parts) > 1:

                    ip = parts[1].strip()

                    # Match ONLY IPv4
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        return ip

                # Check next few lines
                for j in range(i + 1, min(i + 3, len(lines))):

                    next_line = lines[j].strip()

                    if re.match(r"\d+\.\d+\.\d+\.\d+", next_line):
                        return next_line

    except Exception as e:

        print("[-] Failed to get gateway IP")
        print(e)

        sys.exit()

# -------------------------------
# STEP 2: GET REAL MAC
# -------------------------------
def get_mac(ip):

    arp_request = ARP(pdst=ip)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    result = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    if result:

        return result[0][1].hwsrc

    return None

# -------------------------------
# STEP 3: BEEP ALERT
# -------------------------------
def beep_alert():

    for _ in range(5):

        winsound.Beep(1000, 500)

# -------------------------------
# STEP 4: LOG ATTACK
# -------------------------------
def log_attack(ip, real_mac, fake_mac):

    global logged_attackers

    # Prevent duplicate logging
    if fake_mac in logged_attackers:
        return

    logged_attackers.add(fake_mac)

    with open("attack_log.txt", "a") as file:

        file.write("\n")
        file.write("[!] MITM ATTACK DETECTED\n")
        file.write(f"Time: {time.ctime()}\n")
        file.write(f"Gateway IP: {ip}\n")
        file.write(f"Real MAC: {real_mac}\n")
        file.write(f"Fake MAC: {fake_mac}\n")
        file.write("-" * 50)
        file.write("\n")

# -------------------------------
# STEP 5: DETECTION LOGIC
# -------------------------------
def detect_mitm(gateway_ip, real_mac):

    global last_attack_time

    print("\n[*] Monitoring ARP packets...\n")

    attack_active = False

    def process(packet):

        nonlocal attack_active
        global last_attack_time

        if packet.haslayer(ARP):

            if packet[ARP].op == 2:

                sender_ip = packet[ARP].psrc
                sender_mac = packet[ARP].hwsrc

                # Monitor ONLY gateway
                if sender_ip == gateway_ip:

                    # -------------------------------
                    # ATTACK DETECTED
                    # -------------------------------
                    if sender_mac.lower() != real_mac.lower():

                        last_attack_time = time.time()

                        # ALERT ONLY ONCE
                        if not attack_active:

                            print("\n🚨 MITM ATTACK DETECTED🚨")

                            print(f"Target IP    : {gateway_ip}")
                            print(f"Original MAC : {real_mac}")
                            print(f"Spoofed MAC  : {sender_mac}")

                            print("-" * 50)

                            # Alert sound
                            beep_alert()

                            # Save attack log
                            log_attack(
                                gateway_ip,
                                real_mac,
                                sender_mac
                            )

                            print("[+] Attack logged to attack_log.txt")

                            attack_active = True

    # Continuous monitoring loop
    while True:

        sniff(
            filter="arp",
            prn=process,
            store=False,
            timeout=1
        )

        # -------------------------------
        # ATTACK STOPPED
        # -------------------------------
        if attack_active:

            if time.time() - last_attack_time > ATTACK_TIMEOUT:

                print("\n[+] ATTACK STOPPED")

                print(f"Gateway Restored : {gateway_ip}")
                print(f"Current MAC      : {real_mac}")

                print("-" * 50)

                attack_active = False

# -------------------------------
# MAIN PROGRAM
# -------------------------------
def main():

    print("====================================")
    print("      MITM DETECTION SYSTEM")
    print("====================================\n")

    # Get gateway
    gateway_ip = get_gateway()

    if gateway_ip is None:

        print("[-] Could not find valid IPv4 gateway.")

        sys.exit()

    print(f"🌐 Gateway IP : {gateway_ip}")

    # Get MAC
    print("\n🔍 Getting real MAC address...")

    real_mac = get_mac(gateway_ip)

    if real_mac is None:

        print("[-] Could not find MAC address.")

        sys.exit()

    print(f"✅ Gateway MAC: {real_mac}")

    time.sleep(2)

    # Start monitoring
    detect_mitm(
        gateway_ip,
        real_mac
    )

# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\n[INFO] Monitoring stopped by user.")