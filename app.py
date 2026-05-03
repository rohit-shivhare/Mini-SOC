from flask import Flask, render_template, request, jsonify, send_from_directory, g
import threading
import os
from werkzeug.utils import secure_filename
import database
from modules import web_scanner
from modules import secure_transfer
from modules import network_monitor

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper to get DB connection for Flask routes
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = database.get_db_connection()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Start the network sniffer in a background thread
def run_sniffer():
    network_monitor.start_sniffing()

sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
sniffer_thread.start()


# --- Routes ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dummy", methods=['GET', 'POST'])
def dummy_target():
    message = ""
    if request.method == 'POST':
        # Simulate vulnerabilities for the scanner to catch
        username = request.form.get('username', '')
        search = request.form.get('search', '')
        
        if "' OR" in username:
            message = "Database Error: syntax error near '' OR'. Possible SQL Injection!"
        elif search:
             message = f"You searched for: {search}" # Reflects XSS payload
             
    return render_template("dummy_target.html", message=message)

# --- API Endpoints for Dashboard ---

@app.route('/api/traffic')
def get_traffic():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM packets ORDER BY id DESC LIMIT 10")
    packets = [dict(row) for row in c.fetchall()]
    return jsonify(packets)

@app.route('/api/alerts')
def get_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 10")
    alerts = [dict(row) for row in c.fetchall()]
    return jsonify(alerts)

@app.route('/api/scan', methods=['POST'])
def run_scan():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL required"})
    
    # Run scanner
    results = web_scanner.scan_target(url)
    return jsonify(results)

@app.route('/api/file_transfer', methods=['POST'])
def file_transfer():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"})
        
    action = request.form.get('action') # 'encrypt' or 'decrypt'
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            if action == 'encrypt':
                processed_filepath = secure_transfer.encrypt_file(filepath)
            elif action == 'decrypt':
                processed_filepath = secure_transfer.decrypt_file(filepath)
            else:
                 return jsonify({"success": False, "error": "Invalid action"})
                 
            # Return just the filename for downloading
            processed_filename = os.path.basename(processed_filepath)
            return jsonify({"success": True, "filename": processed_filename})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


if __name__ == "__main__":
    # Ensure database is initialized before starting
    database.init_db()
    # Run Flask app
    app.run(debug=True, use_reloader=False) # use_reloader=False prevents running sniffer thread twice