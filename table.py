import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
import re

from scapy.all import sniff, ARP, Ether, srp

# -------------------------------
# GET GATEWAY IP (IPv4 ONLY)
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

                    # Match IPv4 only
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        return ip

                # Check next few lines
                for j in range(i + 1, min(i + 3, len(lines))):

                    next_line = lines[j].strip()

                    if re.match(r"\d+\.\d+\.\d+\.\d+", next_line):
                        return next_line

    except Exception as e:

        print("❌ Error getting gateway:", e)
        sys.exit()


# -------------------------------
# GET REAL MAC
# -------------------------------
def get_mac(ip):

    arp = ARP(pdst=ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    if result:
        return result[0][1].hwsrc

    return None


# -------------------------------
# GLOBALS
# -------------------------------
gateway_ip = get_gateway()

if gateway_ip is None:
    print("❌ Could not find IPv4 gateway")
    sys.exit()

real_mac = get_mac(gateway_ip)

if real_mac is None:
    print("❌ Could not find MAC address")
    sys.exit()

current_mac = real_mac
current_status = "SAFE"

MAX_ROWS = 20
LOG_INTERVAL = 5


# -------------------------------
# GUI SETUP
# -------------------------------
root = tk.Tk()

root.title("ARP Monitoring Dashboard")

root.geometry("850x450")

root.configure(bg="white")


# -------------------------------
# TOP INFO
# -------------------------------
title = tk.Label(
    root,
    text="ARP Monitoring Dashboard",
    font=("Arial", 18, "bold"),
    bg="white"
)

title.pack(pady=10)

gateway_label = tk.Label(
    root,
    text=f"Gateway IP: {gateway_ip}",
    font=("Arial", 13),
    bg="white"
)

gateway_label.pack()

mac_label = tk.Label(
    root,
    text=f"Real MAC: {real_mac}",
    font=("Arial", 13),
    bg="white"
)

mac_label.pack()

status_label = tk.Label(
    root,
    text="SAFE",
    fg="green",
    bg="white",
    font=("Arial", 20, "bold")
)

status_label.pack(pady=10)


# -------------------------------
# TABLE
# -------------------------------
columns = ("Time", "IP", "MAC", "Status")

tree = ttk.Treeview(
    root,
    columns=columns,
    show="headings",
    height=15
)

for col in columns:

    tree.heading(col, text=col)

    tree.column(
        col,
        anchor="center",
        width=180
    )

tree.pack(fill="both", expand=True, padx=10, pady=10)

# Row colors
tree.tag_configure(
    "safe",
    foreground="green"
)

tree.tag_configure(
    "attack",
    foreground="red"
)


# -------------------------------
# UPDATE STATUS LABEL
# -------------------------------
def update_status():

    if current_status == "SAFE":

        status_label.config(
            text="SAFE",
            fg="green"
        )

    else:

        status_label.config(
            text="ATTACK DETECTED",
            fg="red"
        )


# -------------------------------
# ADD TABLE ROW
# -------------------------------
def add_row():

    timestamp = time.strftime("%H:%M:%S")

    tag = (
        "safe"
        if current_status == "SAFE"
        else "attack"
    )

    tree.insert(
        "",
        "end",
        values=(
            timestamp,
            gateway_ip,
            current_mac,
            current_status
        ),
        tags=(tag,)
    )

    # Remove old rows
    if len(tree.get_children()) > MAX_ROWS:

        tree.delete(
            tree.get_children()[0]
        )


# -------------------------------
# PACKET SNIFFER
# -------------------------------
def sniff_thread():

    global current_mac
    global current_status

    def process(packet):

        global current_mac
        global current_status

        if packet.haslayer(ARP):

            if packet[ARP].op == 2:

                sender_ip = packet[ARP].psrc

                sender_mac = packet[ARP].hwsrc

                # Monitor ONLY gateway
                if sender_ip == gateway_ip:

                    current_mac = sender_mac

                    if sender_mac.lower() == real_mac.lower():

                        current_status = "SAFE"

                    else:

                        current_status = "ATTACK"

                    root.after(
                        0,
                        update_status
                    )

    sniff(
        filter="arp",
        iface="Wi-Fi",   # change if needed
        prn=process,
        store=False
    )


# -------------------------------
# LOGGER THREAD
# -------------------------------
def logger_thread():

    while True:

        time.sleep(LOG_INTERVAL)

        root.after(
            0,
            add_row
        )


# -------------------------------
# START THREADS
# -------------------------------
threading.Thread(
    target=sniff_thread,
    daemon=True
).start()

threading.Thread(
    target=logger_thread,
    daemon=True
).start()


# -------------------------------
# RUN GUI
# -------------------------------
root.mainloop()