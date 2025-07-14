import asyncio
import json
import logging
import time
from datetime import datetime
from typing import List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
from pythonjsonlogger import jsonlogger

# Configure structured logging
def setup_logging():
    log_handler = logging.FileHandler('app.log')
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(funcName)s %(lineno)d'
    )
    log_handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)
    
    return logger

app = FastAPI(title="FastAPI Log Streaming Sample", version="1.0.0")
logger = setup_logging()

# Models
class UserModel(BaseModel):
    id: Optional[int] = None
    name: str
    email: str
    age: int

class LogEntry(BaseModel):
    timestamp: str
    level: str
    message: str
    endpoint: str
    response_time: float
    status_code: int
    user_id: Optional[str] = None

# In-memory storage for demo
users_db = []
request_counts = {}

# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Log request
    logger.info(
        "Request started",
        extra={
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "event_type": "request_start"
        }
    )
    
    response = await call_next(request)
    
    # Calculate response time
    process_time = time.time() - start_time
    
    # Track request counts for anomaly detection
    endpoint = request.url.path
    current_hour = datetime.now().hour
    key = f"{endpoint}_{current_hour}"
    request_counts[key] = request_counts.get(key, 0) + 1
    
    # Log response
    logger.info(
        "Request completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "status_code": response.status_code,
            "response_time": process_time,
            "endpoint": endpoint,
            "request_count": request_counts[key],
            "event_type": "request_end"
        }
    )
    
    return response

# API Endpoints
@app.get("/")
async def root():
    logger.info("Root endpoint accessed", extra={"event_type": "endpoint_access"})
    return {"message": "FastAPI Log Streaming Sample"}

@app.get("/users", response_model=List[UserModel])
async def get_users():
    logger.info(f"Retrieved {len(users_db)} users", extra={"event_type": "data_access", "count": len(users_db)})
    return users_db

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = next((u for u in users_db if u.get("id") == user_id), None)
    if not user:
        logger.warning(f"User {user_id} not found", extra={"event_type": "not_found", "user_id": user_id})
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.info(f"Retrieved user {user_id}", extra={"event_type": "user_access", "user_id": user_id})
    return user

@app.post("/users", response_model=UserModel)
async def create_user(user: UserModel):
    user_dict = user.model_dump()
    user_dict["id"] = len(users_db) + 1
    users_db.append(user_dict)
    
    logger.info(
        f"Created user {user_dict['id']}", 
        extra={
            "event_type": "user_created", 
            "user_id": user_dict["id"],
            "user_name": user_dict["name"]
        }
    )
    return user_dict

@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    global users_db
    original_count = len(users_db)
    users_db = [u for u in users_db if u.get("id") != user_id]
    
    if len(users_db) == original_count:
        logger.warning(f"Attempted to delete non-existent user {user_id}", extra={"event_type": "delete_failed", "user_id": user_id})
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.info(f"Deleted user {user_id}", extra={"event_type": "user_deleted", "user_id": user_id})
    return {"message": f"User {user_id} deleted"}

# Simulate some anomalous behavior
@app.get("/simulate-error")
async def simulate_error():
    logger.error("Simulated error endpoint accessed", extra={"event_type": "error_simulation"})
    raise HTTPException(status_code=500, detail="Simulated server error")

@app.get("/simulate-heavy-load")
async def simulate_heavy_load():
    # Simulate a slow endpoint
    await asyncio.sleep(2)
    logger.warning("Heavy load endpoint accessed", extra={"event_type": "heavy_load", "response_time": 2.0})
    return {"message": "Heavy load simulation completed"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

