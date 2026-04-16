from dotenv import load_dotenv
import os

from datetime import datetime, timedelta, date

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import jwt, JWTError

from pydantic import BaseModel

from sqlalchemy.orm import Session, joinedload

from pwdlib import PasswordHash

from app.database import engine, Base, SessionLocal
from app import models

app = FastAPI()
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY není nastavený")

ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
password_hash = PasswordHash.recommended()

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserRead(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True

class StudentCreate(BaseModel):
    first_name: str
    last_name: str
    birth_date: date | None = None
    city: str | None = None

Base.metadata.create_all(bind=engine)

class ClassBasicRead(BaseModel):
    id: int
    name: str
    school_year: str

    class Config:
        from_attributes = True

class ClassRead(BaseModel):
    id: int
    name: str
    school_year: str
    student_count: int

    class Config:
        from_attributes = True

class StudentRead(BaseModel):
    id: int
    first_name: str
    last_name: str
    birth_date: date | None = None
    city: str | None = None
    active: bool
    school_class: ClassBasicRead | None = None

    class Config:
        from_attributes = True

class StudentUpdate(BaseModel):
    first_name: str
    last_name: str
    birth_date: date | None = None
    city: str | None = None
    active: bool

class ParentStudentLinkCreate(BaseModel):
    parent_user_id: int
    student_id: int

class ClassCreate(BaseModel):
    name: str
    school_year: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        user_id: int = payload.get("user_id")

        if username is None:
            raise HTTPException(status_code=401, detail="Neplatný token")

        return {
            "user_id": user_id,
            "username": username,
            "role": role
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Neplatný token")

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Nedostatečná oprávnění")
    return current_user

@app.post("/users", response_model=UserRead)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username už existuje")

    new_user = models.User(
        username=user.username,
        password_hash=password_hash.hash(user.password),
        role=user.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()

    if user is None:
        raise HTTPException(status_code=401, detail="Neplatné přihlašovací údaje")

    if not password_hash.verify(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Neplatné přihlašovací údaje")

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "user_id": user.id}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/")
def read_root():
    return {"message": "API funguje ✅"}


@app.post("/students")
def create_student(student: StudentCreate, db: Session = Depends(get_db)):
    new_student = models.Student(
        first_name=student.first_name,
        last_name=student.last_name,
        birth_date=student.birth_date,
        city=student.city,
        active=True
    )

    db.add(new_student)
    db.commit()
    db.refresh(new_student)

    return new_student

@app.get("/me")
def read_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/students", response_model=list[StudentRead])
def get_students( db: Session = Depends(get_db)):
    students = db.query(models.Student).options(joinedload(models.Student.school_class)).all()

    return students

@app.get("/students/{student_id}", response_model=StudentRead)
def get_student(student_id: int, db: Session = Depends(get_db)):
    student = (
        db.query(models.Student)
        .options(joinedload(models.Student.school_class))
        .filter(models.Student.id == student_id)
        .first()
    )

    if student is None:
        raise HTTPException(status_code=404, detail="Student nenalezen")

    return student

@app.put("/students/{student_id}", response_model=StudentRead)
def update_student(student_id: int, student_data: StudentUpdate, db: Session = Depends(get_db)):
    student = db.query(models.Student).filter(models.Student.id == student_id).first()

    if student is None:
        raise HTTPException(status_code=404, detail="Student nenalezen")

    student.first_name = student_data.first_name
    student.last_name = student_data.last_name
    student.birth_date = student_data.birth_date
    student.city = student_data.city
    student.active = student_data.active

    db.commit()
    db.refresh(student)

    return student

@app.delete("/students/{student_id}")
def delete_student(student_id: int, user=Depends(require_admin), db: Session = Depends(get_db)):
    student = db.query(models.Student).filter(models.Student.id == student_id).first()

    if student is None:
        raise HTTPException(status_code=404, detail="Student nenalezen")

    db.delete(student)
    db.commit()

    return {"message": f"Student s ID {student_id} byl smazán"}

@app.post("/parent-student-links")
def create_parent_student_link(link_data: ParentStudentLinkCreate, db: Session = Depends(get_db)):
    parent_user = db.query(models.User).filter(models.User.id == link_data.parent_user_id).first()
    if parent_user is None:
        raise HTTPException(status_code=404, detail="Parent user nenalezen")

    student = db.query(models.Student).filter(models.Student.id == link_data.student_id).first()
    if student is None:
        raise HTTPException(status_code=404, detail="Student nenalezen")

    if parent_user.role != "parent":
        raise HTTPException(status_code=400, detail="Zadaný user nemá roli parent")

    new_link = models.ParentStudentLink(
        parent_user_id=link_data.parent_user_id,
        student_id=link_data.student_id
    )

    db.add(new_link)
    db.commit()
    db.refresh(new_link)

    return {
        "id": new_link.id,
        "parent_user_id": new_link.parent_user_id,
        "student_id": new_link.student_id
    }

@app.get("/my-students", response_model=list[StudentRead])
def get_my_students(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user["role"] != "parent":
        raise HTTPException(status_code=403, detail="Pouze pro rodiče")

    links = db.query(models.ParentStudentLink).filter(
        models.ParentStudentLink.parent_user_id == current_user["user_id"]
    ).all()

    student_ids = [link.student_id for link in links]

    students = db.query(models.Student).filter(
        models.Student.id.in_(student_ids)
    ).all()

    
    return students

@app.post("/classes")
def create_class(class_data: ClassCreate, db: Session = Depends(get_db)):
    new_class = models.Class(
        name=class_data.name,
        school_year=class_data.school_year
    )
    db.add(new_class)
    db.commit()
    db.refresh(new_class)    

    return new_class

@app.put("/students/{student_id}/assign-class/{class_id}")
def assign_student_to_class(student_id: int, class_id: int, db: Session = Depends(get_db)):
    student = db.query(models.Student).filter(models.Student.id == student_id).first()
    if student is None:
        raise HTTPException(status_code=404, detail="Student nenalezen")

    school_class = db.query(models.Class).filter(models.Class.id == class_id).first()
    if school_class is None:
        
        raise HTTPException(status_code=404, detail="Třída nenalezena")

    student.class_id = class_id

    db.commit()
    db.refresh(student)
    

    return {"message": f"Student {student_id} přiřazen do třídy {class_id}"}

@app.get("/classes", response_model=list[ClassRead])
def get_classes( db: Session = Depends(get_db)):
    classes = db.query(models.Class).all()

    result = []
    for school_class in classes:
        student_count = len(school_class.students)

        result.append({
            "id": school_class.id,
            "name": school_class.name,
            "school_year": school_class.school_year,
            "student_count": student_count
        }) 
    return result

@app.get("/classes/{class_id}/students", response_model=list[StudentRead])
def get_students_by_class(class_id: int, db: Session = Depends(get_db)):

    school_class = db.query(models.Class).filter(models.Class.id == class_id).first()

    if school_class is None:
        raise HTTPException(status_code=404, detail="Třída nenalezena")

    students = (
        db.query(models.Student)
        .options(joinedload(models.Student.school_class))
        .filter(models.Student.class_id == class_id)
        .all()
    )

    return students