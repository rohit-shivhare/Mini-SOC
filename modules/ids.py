import sqlite3
import datetime
import database

def log_alert(alert_type, source_ip, description, severity):
    conn = database.get_db_connection()
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO alerts (timestamp, type, source_ip, description, severity) VALUES (?, ?, ?, ?, ?)",
        (timestamp, alert_type, source_ip, description, severity)
    )
    conn.commit()
    conn.close()
    print(f"[!] IDS ALERT: {alert_type} from {source_ip} - {description}")

def check_for_dos(src_ip):
    # Simple rule: If more than 100 packets from same IP in last 10 seconds -> DoS alert
    conn = database.get_db_connection()
    c = conn.cursor()
    # In SQLite, we can approximate time checks, but for a simple demo we just check the recent packets
    c.execute("SELECT count(*) FROM packets WHERE src_ip = ? ORDER BY id DESC LIMIT 100", (src_ip,))
    count = c.fetchone()[0]
    
    # Check if there's already a recent alert to avoid spamming
    c.execute("SELECT count(*) FROM alerts WHERE source_ip = ? AND type = 'DoS Attack' ORDER BY id DESC LIMIT 1", (src_ip,))
    alert_exists = c.fetchone()[0]

    if count >= 100 and not alert_exists:
        log_alert("DoS Attack", src_ip, "High volume of traffic detected.", "High")
        
    conn.close()

def check_for_port_scan(src_ip):
    # Simple rule: Connection to many different destination ports from single IP
    conn = database.get_db_connection()
    c = conn.cursor()
    c.execute("SELECT count(DISTINCT dst_ip) FROM packets WHERE src_ip = ? ORDER BY id DESC LIMIT 50", (src_ip,))
    count = c.fetchone()[0]
    
    c.execute("SELECT count(*) FROM alerts WHERE source_ip = ? AND type = 'Port Scan' ORDER BY id DESC LIMIT 1", (src_ip,))
    alert_exists = c.fetchone()[0]

    # For demo purposes, we trigger if trying to hit more than 5 distinct "destinations" quickly (or ports if we logged them, here we use dst_ip as a proxy in this simple schema)
    if count >= 5 and not alert_exists:
         log_alert("Port Scan", src_ip, "Suspicious scanning activity detected.", "Medium")
         
    conn.close()
