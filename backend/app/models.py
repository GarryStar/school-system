from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    birth_date = Column(Date, nullable=True)
    city = Column(String(100), nullable=True)
    active = Column(Boolean, default=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)  # admin, teacher, parent

class ParentStudentLink(Base):
    __tablename__ = "parent_student_links"

    id = Column(Integer, primary_key=True, index=True)
    parent_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)