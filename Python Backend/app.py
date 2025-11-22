from flask import Flask, request, jsonify
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, TIMESTAMP, func, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import jwt


from .models import User, Contact
from .database import Base, engine, SessionLocal


SECRET_KEY = "YOUR_SECRET_KEY"

app = Flask(__name__)

# Create DB tables
Base.metadata.create_all(bind=engine)


# --------------------------
# HELPER FUNCTIONS
# --------------------------
def get_db():
    """Creates and returns a database session."""
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()


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
    data = request.json
    db = get_db()

    # Check if phone already exists
    existing = db.query(User).filter(User.phone == data["phone"]).first()
    if existing:
        return jsonify({"error": "Phone already registered"}), 400

    # Create user
    user = User(
        full_name=data["full_name"],
        phone=data["phone"],
        password=generate_password_hash(data["password"]),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token({"user_id": user.id, "role": user.role})
    return jsonify({"user_id": user.id, "access_token": token})

    # return jsonify({
    #     "message": "User created successfully!",
    #     "user_id": user.id,
    #     "phone": user.phone
    # })


@app.post("/login")
def login():
    """Authenticates user and returns JWT token."""
    data = request.json
    db = get_db()

    user = db.query(User).filter(User.phone == data["phone"]).first()

    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token({"user_id": user.id, "role": user.role})

    return jsonify({"access_token": token, "token_type": "bearer"})


@app.get("/me")
@require_auth
def me():
    """Returns authenticated user's profile."""
    db = get_db()
    user = db.query(User).filter(User.id == request.user["user_id"]).first()

    return jsonify(
        {
            "id": user.id,
            "full_name": user.full_name,
            "phone": user.phone,
            "email": user.email,
            "role": user.role,
        }
    )


# --------------------------
# USER UPDATE ROUTES
# --------------------------


@app.patch("/user/update")
@require_auth
def update_user():
    """Updates user profile details."""
    data = request.json
    db = get_db()

    user = db.query(User).filter(User.id == request.user["user_id"]).first()

    allowed_fields = ["email", "dob", "blood_group", "gender"]

    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])

    db.commit()
    db.refresh(user)

    return jsonify({"message": "Profile updated successfully"})


# --------------------------
# CONTACT MANAGEMENT
# --------------------------


@app.post("/contacts")
@require_auth
def add_contact():
    """Adds an emergency contact."""
    data = request.json
    db = get_db()

    contact = Contact(
        user_id=request.user["user_id"],
        name=data["name"],
        phone=data["phone"],
        relation=data.get("relation", "Unknown"),
    )

    db.add(contact)
    db.commit()

    return jsonify({"message": "Contact added successfully"})


@app.get("/contacts")
@require_auth
def list_contacts():
    """Gets all emergency contacts."""
    db = get_db()

    contacts = (
        db.query(Contact).filter(Contact.user_id == request.user["user_id"]).all()
    )

    return jsonify(
        [
            {"id": c.id, "name": c.name, "phone": c.phone, "relation": c.relation}
            for c in contacts
        ]
    )


@app.delete("/contacts/<int:contact_id>")
@require_auth
def delete_contact(contact_id):
    """Deletes a contact."""
    db = get_db()

    contact = (
        db.query(Contact)
        .filter(Contact.id == contact_id, Contact.user_id == request.user["user_id"])
        .first()
    )

    if not contact:
        return jsonify({"error": "Contact not found"}), 404

    db.delete(contact)
    db.commit()

    return jsonify({"message": "Contact removed"})


# --------------------------
# SERVER START
# --------------------------

if __name__ == "__main__":
    app.run(debug=True)
