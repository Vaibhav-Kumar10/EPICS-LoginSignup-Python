from sqlalchemy import Column, Integer, String, TIMESTAMP, func, ForeignKey, Boolean
from database import Base
from sqlalchemy.orm import relationship



# --------------------------
# DATABASE MODELS
# --------------------------



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False, index=True)
    phone = Column(String, unique=True, nullable=True, index=True)  # Nullable for social login
    email = Column(String, unique=True, nullable=True)
    dob = Column(String, nullable=True)
    blood_group = Column(String, nullable=True)
    gender = Column(String, default="Female")
    age = Column(Integer, nullable=True)
    aadhar_number = Column(String, nullable=True)
    address = Column(String, nullable=True)  # User's address
    avatar_url = Column(String, nullable=True) # URL/Path to uploaded image
    avatar_id = Column(Integer, default=1) # Fallback ID
    password = Column(String, nullable=True)  # Nullable for social login users
    role = Column(String, default="USER")  # USER or POLICE

    contacts = relationship("Contact", back_populates="user", cascade="all, delete")
    history = relationship("History", back_populates="user", cascade="all, delete")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete")

    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    last_active_at = Column(TIMESTAMP(timezone=True), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    title = Column(String, nullable=False)
    message = Column(String, nullable=False)
    type = Column(String, default="info") # info, warning, alert
    is_read = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="notifications")

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    name = Column(String)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True)  # Email for emergency contact
    relation = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


    user = relationship("User", back_populates="contacts")


class History(Base):
    __tablename__ = "history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    event_type = Column(String, default="SOS")  # SOS, Safety Check, etc.
    details = Column(String, nullable=True)
    timestamp = Column(TIMESTAMP(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="history")


