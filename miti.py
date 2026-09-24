from scapy.all import ARP, Ether, srp, send
import subprocess
import time
import os
import sys

# -------------------------------
# CONFIG
# -------------------------------
INTERVAL = 1

# -------------------------------
# GET GATEWAY IP
# -------------------------------
def get_gateway():

    try:

        result = subprocess.check_output(
            "ipconfig",
            shell=True
        ).decode()

        lines = result.splitlines()

        for i, line in enumerate(lines):

            if "Default Gateway" in line:

                gateway = line.split(":")[-1].strip()

                # IPv4 on same line
                if gateway and "." in gateway:
                    return gateway

                # Check next few lines
                for j in range(i + 1, min(i + 4, len(lines))):

                    next_line = lines[j].strip()

                    if "." in next_line:
                        return next_line

    except:

        print("[✗] Failed to get gateway IP")
        sys.exit()

# -------------------------------
# GET MAC ADDRESS
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
# SET STATIC ARP
# -------------------------------
def set_static_arp(gateway_ip, real_mac):

    windows_mac = real_mac.replace(":", "-")

    cmd = f"arp -s {gateway_ip} {windows_mac}"

    result = os.system(cmd)

    if result == 0:

        print("[+] Static ARP added")

    else:

        print("[✗] Failed to set static ARP")
        print("[!] Run CMD as Administrator")

        sys.exit()

# -------------------------------
# REMOVE STATIC ARP
# -------------------------------
def remove_static_arp(gateway_ip):

    os.system(f"arp -d {gateway_ip}")

    print("[+] Static ARP removed")

# -------------------------------
# SHOW ARP TABLE
# -------------------------------
def show_arp_table():

    print("\n-------------------------------")
    print("CURRENT ARP TABLE")
    print("-------------------------------\n")

    os.system("arp -a")

# -------------------------------
# SEND CORRECTIVE ARP
# -------------------------------
def restore_arp(gateway_ip, real_mac):

    packet = ARP(
        op=2,
        psrc=gateway_ip,
        hwsrc=real_mac
    )

    send(packet, verbose=False)

# -------------------------------
# MAIN
# -------------------------------
def main():

    print("===================================")
    print(" MITM SMART MITIGATION SYSTEM ")
    print("===================================\n")

    # STEP 1
    gateway_ip = get_gateway()

    print(f"[+] Gateway IP : {gateway_ip}")

    # STEP 2
    real_mac = get_mac(gateway_ip)

    if real_mac is None:

        print("[✗] Failed to fetch gateway MAC")
        sys.exit()

    print(f"[+] Real MAC   : {real_mac}")

    print(f"[+] Interval   : {INTERVAL}s")

    show_arp_table()

    mitigation_active = False

    print("\n[*] Monitoring gateway...\n")

    try:

        while True:

            current_mac = get_mac(gateway_ip)

            if current_mac is None:
                continue

            # -------------------------------
            # ATTACK DETECTED
            # -------------------------------
            if current_mac.lower() != real_mac.lower():

                if not mitigation_active:

                    print("\n[!] MITM ATTACK DETECTED")
                    print(f"Original MAC : {real_mac}")
                    print(f"Spoofed MAC  : {current_mac}")

                    print("\n[+] Starting mitigation...")

                    set_static_arp(
                        gateway_ip,
                        real_mac
                    )

                    mitigation_active = True

                restore_arp(
                    gateway_ip,
                    real_mac
                )

                print("[+] Corrective ARP sent")

            # -------------------------------
            # ATTACK STOPPED
            # -------------------------------
            else:

                if mitigation_active:

                    print("\n[+] Attack stopped")

                    remove_static_arp(
                        gateway_ip
                    )

                    mitigation_active = False

            time.sleep(INTERVAL)

    except KeyboardInterrupt:

        print("\n[!] Stopping system...")

        if mitigation_active:

            remove_static_arp(
                gateway_ip
            )

        print("[+] Cleanup completed")

        sys.exit()

# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":

    main()