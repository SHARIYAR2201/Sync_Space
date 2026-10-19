from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import List

# Database Setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./syncspace_base.db" 
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SQLAlchemy Model
class TaskModel(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    assignee = Column(String)
    status = Column(String, default="Backlog")
    priority = Column(String, default="Medium")
    project = Column(String)

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class TaskCreate(BaseModel):
    title: str
    assignee: str
    status: str
    priority: str
    project: str

class TaskResponse(TaskCreate):
    id: int
    class Config:
        from_attributes = True

app = FastAPI(title="SyncSpace Base API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# REST Endpoints
@app.get("/api/v1/tasks", response_model=List[TaskResponse])
def get_tasks(db: Session = Depends(get_db)):
    return db.query(TaskModel).all()

@app.post("/api/v1/tasks", response_model=TaskResponse)
def create_task(task: TaskCreate, db: Session = Depends(get_db)):
    db_task = TaskModel(**task.model_dump())
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task