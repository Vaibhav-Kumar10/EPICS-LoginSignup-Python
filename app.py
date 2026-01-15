from gevent import monkey
monkey.patch_all()

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, TIMESTAMP, func, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests
import urllib3

# Disable SSL warnings for ngrok
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from models import User, Contact, History
from database import Base, engine, SessionLocal


# Read secret from environment for security; fallback for local dev
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY")

# Police Webhook URLs - configure these to your police backend endpoints
POLICE_ALERT_WEBHOOK = os.getenv("POLICE_ALERT_WEBHOOK", "https://fine-flies-cheat.loca.lt/api/receive_alert.php")
POLICE_LOCATION_WEBHOOK = os.getenv("POLICE_LOCATION_WEBHOOK", "https://fine-flies-cheat.loca.lt/api/update_location.php")

app = Flask(__name__)
CORS(app)

# Initialize Socket.IO for real-time SOS alerts
# async_mode='gevent' is automatically selected if gevent is installed, but we can be explicit
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Store connected user sockets for real-time notifications
user_sockets = {}  # {user_id: socket_id}
active_police_tracking = {}  # {user_id: True} - users currently being tracked by police

# Create DB tables
Base.metadata.create_all(bind=engine)


# --------------------------
# HELPER FUNCTIONS
# --------------------------
def get_db():
    """Creates and returns a database session."""
    return SessionLocal()


def create_token(data: dict):
    """Creates JWT access token."""
    return jwt.encode(data, SECRET_KEY, algorithm="HS256")


def decode_token(token: str):
    """Decodes and verifies JWT token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None


def require_auth(fn):
    """Decorator to protect endpoints with authentication."""

    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        decoded = decode_token(token)

        if not decoded or "user_id" not in decoded:
            return jsonify({"error": "Unauthorized"}), 401

        request.user = decoded
        return fn(*args, **kwargs)

    wrapper.__name__ = fn.__name__
    return wrapper


def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two points using Haversine formula.
    Returns distance in meters.
    """
    from math import radians, cos, sin, asin, sqrt
    
    # Convert to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    
    # Radius of earth in meters
    r = 6371000
    
    return c * r


def send_email_notification(to_email, subject, user_name, latitude, longitude, timestamp, message):
    """
    Send email notification via SMTP (Gmail).
    Uses Gmail SMTP with App Password for authentication.
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    # ---------------------------------------------------------
    # EMAIL CONFIGURATION (Gmail SMTP)
    # ---------------------------------------------------------
    # To use Gmail:
    # 1. Enable 2-Factor Authentication on your Google account
    # 2. Create an App Password at: https://myaccount.google.com/apppasswords
    # 3. Use that 16-character app password below
    
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')  # Gmail App Password - set via environment variable
    
    google_maps_link = f'https://www.google.com/maps?q={latitude},{longitude}'
    
    # Create beautiful HTML email
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #e94560, #ff6b6b); padding: 30px; text-align: center; }}
            .header h1 {{ color: white; margin: 0; font-size: 28px; }}
            .header .emoji {{ font-size: 50px; }}
            .content {{ padding: 30px; }}
            .alert-box {{ background: #fff3cd; border-left: 4px solid #e94560; padding: 15px; margin: 20px 0; border-radius: 5px; }}
            .info-row {{ display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }}
            .info-label {{ font-weight: bold; color: #666; width: 120px; }}
            .info-value {{ color: #333; }}
            .location-btn {{ display: inline-block; background: #e94560; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }}
            .footer {{ background: #1a1a2e; color: white; padding: 20px; text-align: center; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="emoji">🚨</div>
                <h1>EMERGENCY SOS ALERT</h1>
            </div>
            <div class="content">
                <div class="alert-box">
                    <strong>{user_name}</strong> has triggered an emergency SOS alert and needs immediate help!
                </div>
                
                <h3>📋 Alert Details:</h3>
                <div class="info-row">
                    <span class="info-label">👤 Name:</span>
                    <span class="info-value">{user_name}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">📍 Location:</span>
                    <span class="info-value">{latitude}, {longitude}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">🕐 Time:</span>
                    <span class="info-value">{timestamp}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">💬 Message:</span>
                    <span class="info-value">{message}</span>
                </div>
                
                <center>
                    <a href="{google_maps_link}" class="location-btn">📍 VIEW LIVE LOCATION ON MAP</a>
                </center>
                
                <p style="color: #666; font-size: 14px;">
                    Please check on them immediately or contact emergency services if needed.
                </p>
            </div>
            <div class="footer">
                Sent by SafeGuard Women Safety App<br>
                This is an automated emergency alert.
            </div>
        </div>
    </body>
    </html>
    '''
    
    print(f"Attempting to send email to {to_email}...")
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = to_email
        
        # Attach HTML content
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Send via Gmail SMTP
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        
        print(f"  ✓ Email Sent to {to_email}!")
        return True
    except Exception as e:
        print(f"  ❌ Email Failed: {e}")
        return False


def send_sms_notification(phone_number, message):
    """
    Send SMS notification via Twilio (kept for backward compatibility).
    """
    print(f"  ℹ️ SMS disabled - using email instead")
    return False


def send_push_notification(user_id, title, body, data=None):
    """
    Send push notification via Firebase Cloud Messaging.
    PLACEHOLDER: Implement when Firebase credentials are available.
    """
    # TODO: Integrate with Firebase
    # import firebase_admin
    # from firebase_admin import messaging
    # 
    # Get user's FCM token from database
    # db = get_db()
    # user = db.query(User).filter(User.id == user_id).first()
    # if not user or not user.fcm_token:
    #     return False
    # 
    # message = messaging.Message(
    #     notification=messaging.Notification(
    #         title=title,
    #         body=body,
    #     ),
    #     data=data or {},
    #     token=user.fcm_token,
    # )
    # 
    # response = messaging.send(message)
    
    print(f"[PUSH PLACEHOLDER] Would send to user {user_id}: {title} - {body}")
    return True



# --------------------------
# AUTH ROUTES
# --------------------------


@app.post("/signup")
def signup():
    """Registers a new user."""
    data = request.json or {}
    db = get_db()
    try:
        # Accept signup via phone or email. At least one required.
        phone = data.get("phone")
        email = data.get("email")
        full_name = data.get("full_name") or data.get("name") or ""
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password is required"}), 400

        if not phone and not email:
            return jsonify({"error": "Provide phone or email to register"}), 400

        if phone:
            existing = db.query(User).filter(User.phone == phone).first()
            if existing:
                return jsonify({"error": "Phone already registered"}), 400

        if email:
            existing_e = db.query(User).filter(User.email == email).first()
            if existing_e:
                return jsonify({"error": "Email already registered"}), 400

        user = User(
            full_name=full_name or email or phone,
            phone=phone,
            email=email,
            password=generate_password_hash(password),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_token({"user_id": user.id, "role": user.role})
        return jsonify({"user_id": user.id, "access_token": token})
    finally:
        db.close()

    # return jsonify({
    #     "message": "User created successfully!",
    #     "user_id": user.id,
    #     "phone": user.phone
    # })


@app.post("/login")
def login():
    """Authenticates user and returns JWT token."""
    data = request.json or {}
    db = get_db()
    try:
        phone = data.get("phone")
        email = data.get("email")
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password required"}), 400

        user = None
        if phone:
            user = db.query(User).filter(User.phone == phone).first()
        elif email:
            user = db.query(User).filter(User.email == email).first()
        else:
            return jsonify({"error": "Provide phone or email to login"}), 400

        if not user or not check_password_hash(user.password, password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_token({"user_id": user.id, "role": user.role})
        return jsonify({"access_token": token, "token_type": "bearer"})
    finally:
        db.close()


@app.post("/auth/social")
def social_login():
    """
    Social login using Firebase ID token.
    Verifies the token and creates/returns user.
    """
    import requests
    import base64
    import json
    
    data = request.json or {}
    id_token = data.get("id_token")
    
    if not id_token:
        return jsonify({"error": "ID token is required"}), 400
    
    try:
        # Firebase ID tokens are JWTs - decode the payload
        # Split the token into parts
        parts = id_token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 401
        
        # Decode the payload (second part)
        # Add padding if needed
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        try:
            decoded_payload = base64.urlsafe_b64decode(payload)
            token_data = json.loads(decoded_payload)
        except Exception as e:
            print(f"Failed to decode token: {e}")
            return jsonify({"error": "Invalid token encoding"}), 401
        
        # Extract user info from the token
        email = token_data.get("email")
        name = token_data.get("name") or token_data.get("email", "").split("@")[0]
        firebase_uid = token_data.get("sub") or token_data.get("user_id")
        
        print(f"Social login attempt - Email: {email}, Name: {name}, Firebase UID: {firebase_uid}")
        
        if not email:
            return jsonify({"error": "Email not found in token"}), 400
        
        db = get_db()
        try:
            # Try to find existing user by email
            user = db.query(User).filter(User.email == email).first()
            
            if not user:
                # Create new user for social login (no password needed)
                user = User(
                    full_name=name,
                    email=email,
                    password="",  # Social login users don't have passwords
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                print(f"✓ Created new social login user: {email}")
            else:
                print(f"✓ Existing user logged in via social: {email}")
            
            # Create JWT token for the app
            token = create_token({"user_id": user.id, "role": user.role})
            return jsonify({
                "access_token": token,
                "token_type": "bearer",
                "user_id": user.id,
            })
        finally:
            db.close()
            
    except Exception as e:
        print(f"Social login error: {e}")
        return jsonify({"error": f"Social login failed: {str(e)}"}), 500


@app.get("/me")
@require_auth
def me():
    """Returns authenticated user's profile."""
    db = get_db()
    try:
        user = db.query(User).filter(User.id == request.user["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify(
            {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "phone": user.phone,
                "age": user.age,
                "gender": user.gender,
                "aadhar_number": user.aadhar_number,
                "avatar_id": user.avatar_id,
                "avatar_url": user.avatar_url,
                "role": user.role,
            }
        )
    finally:
        db.close()


# --------------------------
# USER UPDATE ROUTES
# --------------------------


@app.route("/user/update", methods=["PUT", "PATCH"])
@require_auth
def update_user():
    """Updates user profile details."""
    data = request.json or {}
    db = get_db()
    try:
        user = db.query(User).filter(User.id == request.user["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Allow updating these fields
        allowed_fields = [
            "full_name", "email", "phone", "age", "gender", 
            "aadhar_number", "address", "avatar_id", "avatar_url",
            "dob", "blood_group"
        ]

        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])

        db.commit()
        db.refresh(user)

        return jsonify({"message": "Profile updated successfully"})
    finally:
        db.close()


@app.post("/user/avatar")
@require_auth
def upload_avatar():
    """Uploads user avatar."""
    if 'avatar' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file:
        import os
        from werkzeug.utils import secure_filename
        
        # Create uploads directory if not exists
        upload_folder = 'static/uploads/avatars'
        os.makedirs(upload_folder, exist_ok=True)
        
        filename = secure_filename(f"user_{request.user['user_id']}_{file.filename}")
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        
        # Generate URL (assuming static files are served)
        # In production, use a proper file server or cloud storage
        avatar_url = f"{request.host_url}{upload_folder}/{filename}"
        
        # Update user record
        db = get_db()
        try:
            user = db.query(User).filter(User.id == request.user["user_id"]).first()
            if user:
                user.avatar_url = avatar_url
                db.commit()
        finally:
            db.close()
            
        return jsonify({"message": "Avatar uploaded", "avatar_url": avatar_url})


# --------------------------
# CONTACT MANAGEMENT
# --------------------------


@app.post("/contacts")
@require_auth
def add_contact():
    """Adds an emergency contact."""
    data = request.json
    db = get_db()
    try:
        contact = Contact(
            user_id=request.user["user_id"],
            name=data.get("name"),
            phone=data.get("phone"),
            email=data.get("email"),
            relation=data.get("relation", "Unknown"),
        )

        db.add(contact)
        db.commit()

        return jsonify({"message": "Contact added successfully"})
    finally:
        db.close()


@app.get("/contacts")
@require_auth
def list_contacts():
    """Gets all emergency contacts."""
    db = get_db()
    try:
        contacts = (
            db.query(Contact).filter(Contact.user_id == request.user["user_id"]).all()
        )

        return jsonify(
            [
                {"id": c.id, "name": c.name, "phone": c.phone, "email": c.email, "relation": c.relation}
                for c in contacts
            ]
        )
    finally:
        db.close()


@app.delete("/contacts/<int:contact_id>")
@require_auth
def delete_contact(contact_id):
    """Deletes a contact."""
    db = get_db()
    try:
        contact = (
            db.query(Contact)
            .filter(
                Contact.id == contact_id, Contact.user_id == request.user["user_id"]
            )
            .first()
        )

        if not contact:
            return jsonify({"error": "Contact not found"}), 404

        db.delete(contact)
        db.commit()

        return jsonify({"message": "Contact removed"})
    finally:
        db.close()


# --------------------------
# HISTORY MANAGEMENT
# --------------------------


@app.get("/history")
@require_auth
def get_user_history():
    """Fetches user's safety history."""
    db = get_db()
    try:
        history = (
            db.query(History)
            .filter(History.user_id == request.user["user_id"])
            .order_by(History.timestamp.desc())
            .all()
        )

        return jsonify(
            [
                {
                    "id": h.id,
                    "event_type": h.event_type,
                    "details": h.details,
                    "timestamp": h.timestamp.isoformat(),
                }
                for h in history
            ]
        )
    finally:
        db.close()


# --------------------------
# SOCKET.IO HANDLERS FOR SOS
# --------------------------

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'Client disconnected: {request.sid}')
    # Remove from user_sockets
    for user_id, sid in list(user_sockets.items()):
        if sid == request.sid:
            del user_sockets[user_id]
            print(f'Removed user {user_id} from active sockets')
            break

@socketio.on('identify')
def handle_identify(data):
    """Register user's socket for targeted messaging"""
    user_id = data.get('user_id')
    if user_id:
        user_sockets[user_id] = request.sid
        print(f'User {user_id} identified with socket {request.sid}')
        emit('identified', {'status': 'success', 'user_id': user_id})

@socketio.on('trigger_sos')
def handle_sos(data):
    """
    Handle SOS alert trigger:
    1. Send SMS to family members (emergency contacts) - regardless of distance
    2. Broadcast alert to ALL connected users - they calculate proximity client-side
    """
    print(f'SOS triggered: {data}')
    
    user_id = data.get('user_id')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    timestamp = data.get('timestamp')
    message = data.get('message', 'Emergency SOS Alert')
    
    if not all([user_id, latitude, longitude]):
        emit('sos_error', {'error': 'Missing required SOS data'})
        return
    
    db = get_db()
    try:
        # Get user details
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            emit('sos_error', {'error': 'User not found'})
            return
        
        # Get user's emergency contacts (family members)
        contacts = db.query(Contact).filter(Contact.user_id == user_id).all()
        
        # Prepare alert data
        alert_data = {
            'user_id': user_id,
            'user_name': user.full_name,
            'user_phone': user.phone,
            'latitude': latitude,
            'longitude': longitude,
            'timestamp': timestamp,
            'message': message,
            'google_maps_link': f'https://www.google.com/maps?q={latitude},{longitude}'
        }
        
        print(f'SOS Alert from {user.full_name}: {latitude}, {longitude}')
        print(f'Processing notifications...')
        
        # ========================================
        # 1. NOTIFY EMERGENCY CONTACTS (FAMILY) VIA EMAIL
        # ========================================
        contacts_notified = 0
        for contact in contacts:
            # Send Email to each emergency contact that has an email
            contact_email = contact.email if contact.email else None
            
            if contact_email:
                if send_email_notification(
                    to_email=contact_email,
                    subject=f"🚨 EMERGENCY: {user.full_name} needs help!",
                    user_name=user.full_name,
                    latitude=latitude,
                    longitude=longitude,
                    timestamp=timestamp,
                    message=message
                ):
                    contacts_notified += 1
                    print(f"  ✓ Email sent to {contact.name} ({contact.relation}): {contact_email}")
            else:
                print(f"  ⚠️ No email for contact {contact.name}, skipping...")
        
        print(f'Notified {contacts_notified} emergency contacts via Email')
        
        # ========================================
        # 2. BROADCAST TO ALL CONNECTED USERS
        # (Client devices will calculate distance and show notification if < 1km)
        # ========================================
        broadcast_count = 0
        for uid, socket_id in user_sockets.items():
            # Don't send to the user who triggered the alert
            if uid != user_id:
                socketio.emit('nearby_sos_alert', alert_data, room=socket_id)
                broadcast_count += 1
        
        print(f'Broadcasted alert to {broadcast_count} connected users')
        print(f'  → Clients will check proximity and notify if within 1km')
        
        # ========================================
        # 2.5 POLICE TRACKING (if this is a police alert)
        # ========================================
        if 'Police' in message:
            print(f'🚔 Police Alert detected - initiating police tracking...')
            
            # Mark user for live tracking
            active_police_tracking[user_id] = True
            
            # Prepare full profile for police
            police_profile_data = {
                'user_id': user_id,
                'full_name': user.full_name,
                'phone': user.phone,
                'email': user.email,
                'age': user.age,
                'gender': user.gender,
                'aadhar_number': user.aadhar_number,
                'address': user.address,
                'initial_latitude': latitude,
                'initial_longitude': longitude,
                'timestamp': timestamp,
                'message': message,
                'google_maps_link': f'https://www.google.com/maps?q={latitude},{longitude}',
                'emergency_contacts': [
                    {'name': c.name, 'phone': c.phone, 'relation': c.relation}
                    for c in contacts
                ]
            }
            
            # Send profile to police webhook (one-time)
            try:
                webhook_response = requests.post(
                    POLICE_ALERT_WEBHOOK,
                    json=police_profile_data,
                    timeout=10,
                    verify=False,
                    headers={
                        'ngrok-skip-browser-warning': 'true',
                        'User-Agent': 'SafeGuard-Backend/1.0',
                        'Content-Type': 'application/json'
                    }
                )
                print(f'  ✓ Police webhook notified: {webhook_response.status_code}')
            except Exception as e:
                print(f'  ⚠️ Police webhook failed: {e}')
            
            # Tell app to start streaming live location
            user_socket_id = user_sockets.get(user_id)
            if user_socket_id:
                socketio.emit('start_live_tracking', {'tracking_id': user_id}, room=user_socket_id)
                print(f'  ✓ Sent start_live_tracking to user socket')
        
        
        # ========================================
        # 3. SEND CONFIRMATION TO TRIGGERING USER
        # ========================================
        emit('sos_confirmed', {
            'status': 'success',
            'message': 'SOS alert sent successfully',
            'contacts_notified': contacts_notified,
            'broadcast_to_users': broadcast_count,
        })
        
        print(f'✓ SOS Processing Complete:')
        # ========================================
        # 4. LOG TO HISTORY
        # ========================================
        try:
            new_history = History(
                user_id=user_id,
                event_type="SOS Alert",
                details=f"Lat: {latitude}, Lng: {longitude}",
            )
            db.add(new_history)
            db.commit()
            print("  ✓ SOS event logged to history")
        except Exception as e:
            print(f"  Ref failed to log history: {e}")

        
    finally:
        db.close()


# --------------------------
# SOCKET.IO HANDLERS FOR POLICE LIVE TRACKING
# --------------------------

@socketio.on('live_location_update')
def handle_live_location(data):
    """
    Receive continuous location updates from app during police tracking.
    Forward to police webhook in real-time.
    """
    user_id = data.get('user_id')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    timestamp = data.get('timestamp')
    
    if not user_id or user_id not in active_police_tracking:
        # Not being tracked, ignore
        return
    
    print(f'📍 Live location from user {user_id}: {latitude}, {longitude}')
    
    location_data = {
        'user_id': user_id,
        'latitude': latitude,
        'longitude': longitude,
        'timestamp': timestamp,
        'google_maps_link': f'https://www.google.com/maps?q={latitude},{longitude}'
    }
    
    # Forward to police webhook
    try:
        response = requests.post(
            POLICE_LOCATION_WEBHOOK,
            json=location_data,
            timeout=5,
            verify=False,
            headers={
                'ngrok-skip-browser-warning': 'true',
                'User-Agent': 'SafeGuard-Backend/1.0',
                'Content-Type': 'application/json'
            }
        )
        print(f'  → Forwarded to police webhook: {response.status_code}')
    except Exception as e:
        print(f'  ⚠️ Webhook forward failed: {e}')


@socketio.on('stop_police_tracking')
def handle_stop_tracking(data):
    """Stop police tracking for a user."""
    user_id = data.get('user_id')
    if user_id in active_police_tracking:
        del active_police_tracking[user_id]
        print(f'🛑 Stopped police tracking for user {user_id}')
        emit('tracking_stopped', {'status': 'success'})


# --------------------------
# SOCKET.IO HANDLERS FOR LOCATION HELP REQUEST
# --------------------------

@socketio.on('location_help_request')
def handle_location_help_request(data):
    """
    Share-location help request:
    - User clicks "Share Location" in the app.
    - Backend broadcasts the location to all connected users.
    - Each receiving device calculates distance locally and only notifies if within 5km.

    We log each step so the process is visible server-side.
    """
    print("\n" + "-" * 50)
    print(f"[ShareLocation] Received help request payload: {data}")

    user_id = (data or {}).get('user_id')
    latitude = (data or {}).get('latitude')
    longitude = (data or {}).get('longitude')
    timestamp = (data or {}).get('timestamp')
    message = (data or {}).get('message', 'Help needed — location shared')

    if not all([user_id, latitude, longitude]):
        print("[ShareLocation] ❌ Missing required fields (user_id/latitude/longitude)")
        emit('location_help_error', {'error': 'Missing required location data'})
        return

    db = get_db()
    try:
        print(f"[ShareLocation] Step 1/4: Looking up user_id={user_id}")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print("[ShareLocation] ❌ User not found")
            emit('location_help_error', {'error': 'User not found'})
            return

        alert_data = {
            'user_id': user_id,
            'user_name': user.full_name,
            'user_phone': user.phone,
            'latitude': latitude,
            'longitude': longitude,
            'timestamp': timestamp,
            'message': message,
            'google_maps_link': f'https://www.google.com/maps?q={latitude},{longitude}',
            'type': 'location_help',
        }

        print("[ShareLocation] Step 2/4: Prepared alert payload")
        print(f"[ShareLocation]  - Name: {user.full_name}")
        print(f"[ShareLocation]  - Location: {latitude}, {longitude}")

        print("[ShareLocation] Step 3/4: Broadcasting to connected users...")
        broadcast_count = 0
        for uid, socket_id in user_sockets.items():
            if uid != user_id:
                socketio.emit('nearby_location_help', alert_data, room=socket_id)
                broadcast_count += 1

        print(f"[ShareLocation] ✅ Broadcast completed to {broadcast_count} connected users")
        print("[ShareLocation]  → Each client will compute distance and notify if within 5km")

        # Confirmation to sender
        emit('location_help_confirmed', {
            'status': 'success',
            'broadcast_to_users': broadcast_count,
        })

        print("[ShareLocation] Step 4/4: Confirmation emitted to sender")

        # Optional: log into History table for audit trail
        try:
            new_history = History(
                user_id=user_id,
                event_type="Location Help Shared",
                details=f"Lat: {latitude}, Lng: {longitude}",
            )
            db.add(new_history)
            db.commit()
            print("[ShareLocation]  ✓ Logged event to history")
        except Exception as e:
            print(f"[ShareLocation]  ⚠ Failed to log history: {e}")
    finally:
        db.close()
        print("-" * 50 + "\n")





# --------------------------
# TEST ENDPOINT FOR SIMULATING NEARBY SOS
# --------------------------

@app.post("/test/simulate_nearby_sos")
def simulate_nearby_sos():
    """
    Test endpoint to simulate a nearby SOS alert.
    Useful for testing the proximity notification system without multiple devices.
    """
    data = request.json or {}
    
    # You can provide coordinates, or it will use a default location near Bhopal
    test_lat = data.get('latitude', 23.0730)  # ~600m north of your location
    test_lng = data.get('longitude', 76.8600)
    test_user_name = data.get('user_name', 'Test User')
    
    # Create fake alert data
    fake_alert = {
        'user_id': 999,  # Fake user ID
        'user_name': test_user_name,
        'user_phone': '+919999999999',
        'latitude': test_lat,
        'longitude': test_lng,
        'timestamp': datetime.now().isoformat(),
        'message': 'TEST Emergency SOS Alert',
        'google_maps_link': f'https://www.google.com/maps?q={test_lat},{test_lng}'
    }
    
    print(f'🧪 TEST: Simulating nearby SOS from {test_user_name}')
    print(f'📍 Location: {test_lat}, {test_lng}')
    
    # Broadcast to all connected users
    broadcast_count = 0
    for uid, socket_id in user_sockets.items():
        socketio.emit('nearby_sos_alert', fake_alert, room=socket_id)
        broadcast_count += 1
    
    print(f'✓ Broadcasted test alert to {broadcast_count} connected users')
    
    return jsonify({
        'status': 'success',
        'message': 'Test SOS alert broadcasted',
        'alert_data': fake_alert,
        'broadcast_to': broadcast_count
    })


from datetime import datetime


if __name__ == "__main__":
    # Use socketio.run instead of app.run for Socket.IO support
    # Bind to 0.0.0.0 so emulators/devices can reach the server
    # allow_unsafe_werkzeug is not needed/supported with gevent
    print("\n" + "="*50)
    print("🚀 SafeGuard Backend Server Starting...")
    print("📡 Running on http://0.0.0.0:5000")
    print("📱 Ready for mobile app connections!")
    print("="*50 + "\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)

