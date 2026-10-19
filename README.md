# SyncSpace | Full-Stack Team Collaboration Platform

SyncSpace is a unified workspace application that combines project management, task tracking, team communication, and productivity analytics. This repository contains the base MVP (Minimum Viable Product) featuring a React frontend and a FastAPI backend with real-time WebSockets.

## Tech Stack
* **Frontend:** React 18, Tailwind CSS, Lucide Icons (Standalone HTML setup)
* **Backend:** Python, FastAPI, SQLAlchemy (SQLite for local development), WebSockets

## Quick Start Guide

### 1. Start the Backend
Navigate to the backend directory, install the dependencies, and start the FastAPI server.

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000