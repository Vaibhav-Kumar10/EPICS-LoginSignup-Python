#!/usr/bin/env python3
"""
Mock Police Webhook Server for Testing
Receives profile alerts and live location updates from SafeGuard backend.
"""
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

@app.route('/alert', methods=['POST'])
def receive_alert():
    """Receive initial profile alert from SOS 2"""
    data = request.json
    print("\n" + "="*60)
    print("🚨 EMERGENCY ALERT RECEIVED")
    print("="*60)
    print(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"👤 Name: {data.get('full_name')}")
    print(f"📞 Phone: {data.get('phone')}")
    print(f"📧 Email: {data.get('email')}")
    print(f"🎂 Age: {data.get('age')}")
    print(f"⚧ Gender: {data.get('gender')}")
    print(f"🆔 Aadhar: {data.get('aadhar_number')}")
    print(f"🏠 Address: {data.get('address')}")
    print(f"📍 Initial Location: {data.get('initial_latitude')}, {data.get('initial_longitude')}")
    print(f"🗺️  Map: {data.get('google_maps_link')}")
    print(f"💬 Message: {data.get('message')}")
    print("\n📋 Emergency Contacts:")
    for contact in data.get('emergency_contacts', []):
        print(f"   - {contact.get('name')} ({contact.get('relation')}): {contact.get('phone')}")
    print("="*60 + "\n")
    return jsonify({"status": "received", "message": "Alert acknowledged"})

@app.route('/location', methods=['POST'])
def receive_location():
    """Receive live location updates"""
    data = request.json
    lat = data.get('latitude')
    lng = data.get('longitude')
    ts = data.get('timestamp', '')
    print(f"📍 LIVE: User {data.get('user_id')} @ ({lat:.6f}, {lng:.6f}) - {ts[:19]}")
    return jsonify({"status": "received"})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚔 MOCK POLICE WEBHOOK SERVER")
    print("📡 Running on http://0.0.0.0:5001")
    print("Waiting for alerts from SafeGuard backend...")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5001, debug=False)
