# Import additional modules
import logging
from fastapi import FastAPI
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List

app = FastAPI()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Define user model for authentication
class User(BaseModel):
    username: str
    password: str

# testing (replace with actual user authentication logic)
test_users_db = {
    "test_user": {
        "username": "fakeuser",
        "password": "fakepassword",
    }
}

# Function to authenticate user
def authenticate_user(user: User):
    if user.username in test_users_db:
        if user.password == test_users_db[user.username]["password"]:
            return True
    return False

# Function to get current user based on authentication token
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = test_users_db.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user

# Endpoint for generating a new license key (requires authentication)
@app.get("/generate-license/")
async def generate_license(current_user: User = Depends(get_current_user)):
    expiration_date = datetime.utcnow() + timedelta(days=31)
    license_key = "generated_license_key"  # still gotta ask Juan for license generation method
    license_data = {
        "license_key": license_key,
        "expiration_date": expiration_date,
        "allowed_ips": []  # Initialize with an empty list
    }
    license_collection.insert_one(license_data)
    return {"license_key": license_key, "expiration_date": expiration_date}

# Endpoint for activating a license (requires authentication)
@app.post("/activate-license/")
async def activate_license(license_key: str, ip_address: str, current_user: User = Depends(get_current_user)):
    if not check_license(license_key):
        raise HTTPException(status_code=400, detail="Invalid license key or expired license")
    if not check_device_limit(license_key):
        raise HTTPException(status_code=400, detail="Maximum device limit reached")
    # Add the new IP address to the allowed list
    license_collection.update_one({"license_key": license_key}, {"$addToSet": {"allowed_ips": ip_address}})
    return {"message": "License activated successfully"}

# Endpoint for deactivating a license (requires authentication)
#still to implement..already fucked from the other functions


# Endpoint for verifying a license (requires authentication)
@app.post("/verify-license/")
async def verify_license(license_key: str, ip_address: str, current_user: User = Depends(get_current_user)):
    if check_license(license_key) and ip_address in get_allowed_ips(license_key):
        return {"valid": True}
    else:
        return {"valid": False}
