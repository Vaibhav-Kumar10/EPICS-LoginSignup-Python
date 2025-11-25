import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, TIMESTAMP, func, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

from models import User, Contact
from database import Base, engine, SessionLocal


# Read secret from environment for security; fallback for local dev
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY")

app = Flask(__name__)
CORS(app)

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
                "phone": user.phone,
                "email": user.email,
                "role": user.role,
            }
        )
    finally:
        db.close()


# --------------------------
# USER UPDATE ROUTES
# --------------------------


@app.patch("/user/update")
@require_auth
def update_user():
    """Updates user profile details."""
    data = request.json
    db = get_db()
    try:
        user = db.query(User).filter(User.id == request.user["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        allowed_fields = ["email", "dob", "blood_group", "gender"]

        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])

        db.commit()
        db.refresh(user)

        return jsonify({"message": "Profile updated successfully"})
    finally:
        db.close()


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
                {"id": c.id, "name": c.name, "phone": c.phone, "relation": c.relation}
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
# SERVER START
# --------------------------

if __name__ == "__main__":
    # Bind to 0.0.0.0 so emulators/devices can reach the server
    app.run(host="0.0.0.0", port=5000, debug=True)
