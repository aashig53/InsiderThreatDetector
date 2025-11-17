from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime, timedelta
import os 
from collections import defaultdict  

# --- Database Setup ---
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, "alerts.db")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Model ---
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(50))
    file_path = db.Column(db.String(500))
    file_name = db.Column(db.String(255))
    user = db.Column(db.String(100))
    suspicion_level = db.Column(db.Integer, default=0) # 0=Normal, 1=Suspicious, 2=Critical

    def __repr__(self):
        return f'<Alert {self.action} by {self.user}>'

# --- Custom Functions ---

@app.template_filter('to_ist')
def to_ist(utc_dt):
    """Converts a UTC datetime object to IST."""
    if not utc_dt:
        return ""
    ist_dt = utc_dt + timedelta(hours=5, minutes=30)
    return ist_dt.strftime('%Y-%m-%d %H:%M:%S')

def check_for_anomaly(alert_data, alert_time_utc):
    file_name_lower = alert_data.get('file_name', '').lower()

    # --- Rule 0: Critical (Level 2) ---
    if 'legacy_credentials_' in file_name_lower:
        return 2 

    # --- Rule 1: Suspicious (Level 1) - Time ---
    ist_time = alert_time_utc + timedelta(hours=5, minutes=30)
    if ist_time.hour < 7 or ist_time.hour >= 22:
        return 1 

    # --- Rule 2: Suspicious (Level 1) - Keywords ---
    suspicious_keywords = ['confidential', 'salary', 'private', 'password']
    for keyword in suspicious_keywords:
        if keyword in file_name_lower:
            return 1 

    return 0

# --- Server Routes ---

@app.route("/")
def index():
    return "Hello, this is the Insider Threat Server!"

@app.route("/log", methods=['POST'])
def log_activity():
    data = request.json
    current_time = datetime.utcnow()
    
    sus_level = check_for_anomaly(data, current_time)

    new_alert = Alert(
        timestamp=current_time,
        action=data.get('action'),
        file_path=data.get('file_path'),
        file_name=data.get('file_name'),
        user=data.get('user'),
        suspicion_level=sus_level 
    )
    
    db.session.add(new_alert)
    db.session.commit()

    print(f"--- ALERT LOGGED TO DB ---")
    if sus_level == 2:
        print(f"*** CRITICAL ACTIVITY DETECTED ***")
    elif sus_level == 1:
        print(f"*** SUSPICIOUS ACTIVITY DETECTED ***")
    
    print(f"User:   {data.get('user')}")
    print(f"Action: {data.get('action')}")
    print(f"File:   {data.get('file_name')}")
    print(f"--------------------------\n")
    
    return jsonify({"status": "success", "message": "Log received"})

@app.route("/dashboard")
def dashboard():
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template("dashboard.html", alerts=all_alerts)

@app.route("/dashboard_data")
def dashboard_data():
    
    # Get total alerts and suspicious alerts
    total_alerts = db.session.query(Alert).count()
    suspicious_alerts = db.session.query(Alert).filter(Alert.suspicion_level > 0).count()

    # Get counts by action
    actions_data = db.session.query(
        Alert.action, func.count(Alert.action)
    ).group_by(Alert.action).all()
    
    # Get alerts over time
    alerts_last_24 = Alert.query.filter(
        Alert.timestamp >= (datetime.utcnow() - timedelta(hours=24))
    ).all()
    
    # Group by IST hour
    alerts_by_ist_hour = defaultdict(int)
    for alert in alerts_last_24:
        ist_time = alert.timestamp + timedelta(hours=5, minutes=30)
        hour_str = ist_time.strftime('%Y-%m-%d %H:00')
        alerts_by_ist_hour[hour_str] += 1
    
    # Generate chart labels and data 
    now_ist = datetime.utcnow() + timedelta(hours=5, minutes=30)
    chart_labels = []
    chart_data = []
    for i in range(24, -1, -1): 
        hour_check_ist = now_ist - timedelta(hours=i)
        hour_label = hour_check_ist.strftime('%Y-%m-%d %H:00')
        chart_labels.append(hour_label)
        chart_data.append(alerts_by_ist_hour.get(hour_label, 0))

    # Get counts by file type 
    file_types_data = defaultdict(int)
    all_alerts_for_types = Alert.query.all()  
    for alert in all_alerts_for_types:
        file_name = alert.file_name or ""
        ext = file_name.split('.')[-1].lower() if '.' in file_name else 'no_ext'
        if ext in ['docx', 'doc']:
            ext = 'doc'
        elif ext in ['xlsx', 'xls']:
            ext = 'xls'
        elif ext in ['jpeg', 'jpg']:
            ext = 'jpg'
        elif ext in ['png']:
            ext = 'png'
        file_types_data[ext] += 1
    
    # Convert to lists for Chart.js
    file_types_labels = list(file_types_data.keys())
    file_types_counts = list(file_types_data.values())

    # Format data for Chart.js
    return jsonify({
        'stats': {
            'total_alerts': total_alerts,
            'suspicious_alerts': suspicious_alerts
        },
        'actions_chart': {
            'labels': [a[0] for a in actions_data],
            'data': [a[1] for a in actions_data]
        },
        'time_chart': {
            'labels': chart_labels,
            'data': chart_data
        },
        'file_types_chart': {
            'labels': file_types_labels,
            'data': file_types_counts
        }
    })

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)