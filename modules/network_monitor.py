from scapy.all import sniff, IP, TCP, UDP
import datetime
import database
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import ids

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Other"
        length = len(packet)
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
            
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save to DB
        try:
            conn = database.get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?, ?)",
                (timestamp, src_ip, dst_ip, protocol, length)
            )
            conn.commit()
            conn.close()
            
            # Pass to IDS
            ids.check_for_dos(src_ip)
            ids.check_for_port_scan(src_ip)
            
        except Exception as e:
            print(f"Error logging packet: {e}")

import time
import random
import threading

def simulate_traffic():
    print("[*] Falling back to Simulation Mode. Generating dummy traffic...")
    counter = 0
    while True:
        counter += 1
        # Normal random traffic
        src_ip = f"192.168.1.{random.randint(2, 50)}"
        dst_ip = f"10.0.0.{random.randint(1, 5)}"
        
        # Every 10 seconds, simulate a DoS or Port Scan explicitly from a single attacker IP
        if counter % 10 == 0:
            src_ip = "192.168.1.99" # Attacker IP
            # Burst 100 packets to trigger DoS immediately
            for _ in range(105):
                try:
                    conn = database.get_db_connection()
                    c = conn.cursor()
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?, ?)", (timestamp, src_ip, dst_ip, "TCP", 1500))
                    conn.commit()
                    conn.close()
                except: pass
        
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        length = random.randint(40, 1500)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            conn = database.get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?, ?)",
                (timestamp, src_ip, dst_ip, protocol, length)
            )
            conn.commit()
            conn.close()
            
            # Pass to IDS
            ids.check_for_dos(src_ip)
            ids.check_for_port_scan(src_ip)
            
        except Exception as e:
            print(f"[!] Simulation Error: {e}")
            
        time.sleep(random.uniform(0.5, 1.5))

def start_sniffing(interface=None):
    print(f"[*] Starting network sniffer on {interface if interface else 'default'} interface...")
    try:
        # Try a quick test sniff to see if we have permissions
        sniff(count=1, filter="ip", timeout=2)
        print("[*] Sniffer has permissions, starting continuous capture...")
        sniff(prn=packet_callback, store=False, filter="ip", iface=interface)
    except Exception as e:
        print(f"[!] Sniffer Error or no privileges: {e}")
        # Start simulation loop instead
        simulate_traffic()

if __name__ == "__main__":
    database.init_db()
    start_sniffing()
