from sqlalchemy import Column, Integer, String, TIMESTAMP, func, ForeignKey
from .database import Base
from sqlalchemy.orm import relationship



# --------------------------
# DATABASE MODELS
# --------------------------



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False, index=True)
    phone = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=True)
    dob = Column(String, nullable=True)
    blood_group = Column(String, nullable=True)
    gender = Column(String, default="Female")
    password = Column(String, nullable=False)
    role = Column(String, default="USER")  # USER or POLICE

    contacts = relationship("Contact", back_populates="user", cascade="all, delete")


    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    last_active_at = Column(TIMESTAMP(timezone=True), nullable=True)

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    name = Column(String)
    phone = Column(String)
    relation = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="contacts")

