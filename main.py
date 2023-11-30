from fastapi import FastAPI, HTTPException, Request, Form, status
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.responses import FileResponse
from dht_module import DHTModel
from user_management import UserManager
from kademlia.network import Server
from cryptography.fernet import Fernet
import hashlib
import time
import base64
import sys
import asyncio
import logging
import concurrent.futures
import json
import binascii
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from asyncio import queues
from asyncio import run_coroutine_threadsafe
import bcrypt
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import secrets
import tkinter.simpledialog as simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import asyncio
import uvicorn
from fastapi import FastAPI
from dht_module import DHTModel
import asyncio
import sys
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
import uuid
from fastapi import Body
from fastapi import FastAPI, HTTPException, Request, Form, status, File, UploadFile
import logging
from fastapi.responses import StreamingResponse
import io 
from typing import List
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from fastapi import Response
from datetime import datetime, timedelta
import pickle
from fastapi import Depends, HTTPException, status
from fastapi import WebSocket
from pydantic import BaseModel, Field
from typing import List
from datetime import datetime
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles



from fastapi import Depends, HTTPException, status
from secure_memory_module import SecureMemoryManager
import secrets

def generate_session_id():
    return secrets.token_urlsafe()

class UsernamesQuery(BaseModel):
    usernames: List[str] = Field(...)
    current_user: str


class PostContent(BaseModel):
    post_content: str
#active_connections = {}

secure_memory_manager = SecureMemoryManager(size=32768)  # Example size




class UserInfo(BaseModel):
    name: str
    occupation: str
    location: str
    birthday: str
    interests: List[str]


class PicInfo(BaseModel):
    file: str



def generate_symmetric_key():
    return os.urandom(32)  # For AES-256

def encrypt_with_public_key(public_key, data):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

logger = logging.getLogger("uvicorn.error")
# Initialize FastAPI and templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# Load LOKI spec
with open('lokispec.json', 'r') as f:
    lokispec = json.load(f)

# Initialize global variables
dht = None
user_manager = None

# Routes
@app.get("/")
def get_login_register(request: Request, message: str = None):
    return templates.TemplateResponse("login_register.html", {"request": request, "message": message})

def get_keys_from_secure_storage():
    stored_data = secure_memory_manager.access()
    private_key, symmetric_key = stored_data.split(':')
    return private_key, symmetric_key

@app.post("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id:
        secure_memory_manager.wipe(session_id)
        response.delete_cookie(key="session_id")
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


def get_current_user(request: Request):
    logger.info(f"request:{request}")
    session_id = request.cookies.get("session_id")
    logger.info(f"session_id:{session_id}")
    if session_id:
        user_data = secure_memory_manager.access(session_id)
        if user_data:
            return user_data
        else:
            raise HTTPException(status_code=401, detail="Session not found or expired")
    else:
        raise HTTPException(status_code=401, detail="Unauthorized")




    
@app.post("/accept_friend_request/{username}/{friend_username}")
async def accept_friend_request_endpoint(request: Request, username: str, friend_username: str):
    user_data = get_current_user(request)
    logger.info(user_data) 
    if user_data['username'] != username:
        raise HTTPException(status_code=403, detail="Unauthorized action")

    password = user_data['password']
    success = await user_manager.accept_friend_request(username, friend_username, password)
    if success:
        return JSONResponse(content={"message": "Friend request accepted"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Failed to accept friend request"}, status_code=400)

@app.post("/reject_friend_request/{username}/{friend_username}")
async def reject_friend_request_endpoint(username: str, friend_username: str):
    success = await user_manager.reject_friend_request(username, friend_username)
    if success:
        return JSONResponse(content={"message": "Friend request rejected"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Failed to reject friend request"}, status_code=400)
        
@app.get("/profile/{username}")
async def get_profile(request: Request, username: str):
        # Retrieve current user's data from secure memory
    user_data = get_current_user(request)
    logger.info(user_data) 
    if user_data['username'] != username:
        raise HTTPException(status_code=403, detail="Unauthorized action")

    password = user_data['password']
    logger.info(f"trying username:{username} and password:{password}")
    
    profile_data =  await user_manager.get_user_profile(username, password) 
    return templates.TemplateResponse("profile.html", {"request": request, "profile": profile_data, "server_port": web_port})


@app.post("/action")
async def form_action(request: Request, username: str = Form(...), password: str = Form(...), action: str = Form(...)):
    if action == "login":
        authenticated, user_keys = await user_manager.authenticate_user(username, password)

        if authenticated:
            logger.info(f"user_keys:{user_keys}")
            # Generate session ID and store user data in secure memory
            session_id = generate_session_id()
            private_key_pem = user_keys['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Store only the necessary information
            user_info = {
                "username": username, 
                "private_key_pem": private_key_pem, 
                "symmetric_key": user_keys['symmetric_key'], 
                "password": password
            }


            secure_memory_manager.store(session_id, user_info)

            # Create a RedirectResponse and set the cookie on it
            redirect_response = RedirectResponse(url=f"/profile/{username}", status_code=status.HTTP_302_FOUND)
            redirect_response.set_cookie(key="session_id", value=session_id, httponly=True, secure=True)
            return redirect_response
        else:
            return templates.TemplateResponse("login_register.html", {"request": request, "message": "Invalid username or password."})

    elif action == "register":
        try:
            # Check if username already exists
            if await user_manager.get_user_public_key(username):
                raise HTTPException(status_code=400, detail="Username already exists")

            # User's RSA keys generation and serialization
            private_key, public_key_serialized, symmetric_key = await user_manager.create_user(username, password)

            # Save additional user details (if any) and handle user profile creation

            # Respond with success message or redirect
            return templates.TemplateResponse("login_register.html", {"request": request, "message": "Registration successful. Please login."})
        
        except HTTPException as http_exc:
            return templates.TemplateResponse("login_register.html", {"request": request, "message": str(http_exc.detail)})
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return templates.TemplateResponse("login_register.html", {"request": request, "message": "Registration failed due to an internal error."})

    else:
        return templates.TemplateResponse("login_register.html", {"request": request, "message": "Invalid action."})




@app.get("/get_friends/{username}")
async def get_friends(request: Request, username: str):
    session_id = request.cookies.get("session_id")
    user_data = secure_memory_manager.access(session_id)
    password = user_data["password"]
    symm_key = user_data["symmetric_key"]    
    profile= await user_manager.get_user_profile(username, password)

    if profile is None:
        return JSONResponse(content={"message": "Failed to retrieve user profile"}, status_code=400) 
      
    friends = await user_manager.get_user_friends(username)
    if friends is not None:
        return JSONResponse(content={"friends": friends}, status_code=200)
    else:
        return JSONResponse(content={"message": "Friends list not found"}, status_code=404)


# Correct retrieval of pending friend requests
@app.get("/get_friend_requests/{username}")
async def get_friend_requests(request: Request, username: str):
    session_id = request.cookies.get("session_id")
    user_data = secure_memory_manager.access(session_id)
    password = user_data["password"]
    symm_key = user_data["symmetric_key"]    
    profile= await user_manager.get_user_profile(username, password)

    if profile is None:
        return JSONResponse(content={"message": "Failed to retrieve user profile"}, status_code=400) 
    try:
        friend_requests = await user_manager.get_pending_friend_requests(username, password)
        if friend_requests:
            logger.info(friend_requests)
            return JSONResponse(content={"friend_requests": friend_requests}, status_code=200)
        else:
            return JSONResponse(content={"message": "No friend requests found"}, status_code=404)
    except Exception as e:
        return JSONResponse(content={"message": "Internal server error"}, status_code=500)



@app.post("/update_user_info/{username}")
async def update_user_info(request: Request, username: str, user_info: UserInfo):
    # Retrieve session information
    session_id = request.cookies.get("session_id")
    user_data = secure_memory_manager.access(session_id)
    password = user_data["password"]
    
    # Fetch the current user profile
    profile = await user_manager.get_user_profile(username, password)
    if profile is None:
        return JSONResponse(content={"message": "Failed to retrieve user profile"}, status_code=400)

    # Update the profile data with new information
    profile.update(user_info.dict())

    # Encrypt and store the updated profile using set_user_profile
    update_success = await user_manager.set_user_profile(username, password, profile)
    if update_success:
        return JSONResponse(content={"message": "User information updated successfully"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Failed to update user profile"}, status_code=500)



# Sending friend requests and notifying via WebSocket
@app.post("/send_friend_request/{from_username}/{to_username}")
async def send_friend_request_endpoint(request: Request, from_username: str, to_username: str):
        # Retrieve session information
    session_id = request.cookies.get("session_id")
    user_data = secure_memory_manager.access(session_id)
    password = user_data["password"]
    success = await user_manager.send_friend_request(from_username, to_username, password)
    if success:
        #if to_username in active_connections:
            #await active_connections[to_username].send_text(f"New friend request from {from_username}")
        return JSONResponse(content={"message": "Friend request sent"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Failed to send friend request"}, status_code=500)




@app.post("/create_post/{username}")
async def create_post(request: Request, username: str, post: PostContent):
        # Retrieve current user's data from secure memory
    logger.info(f"correctly called create post. post content: {post}")
    user_data = get_current_user(request)
    if user_data['username'] != username:
        raise HTTPException(status_code=403, detail="Unauthorized action")
    
    password = user_data["password"]
    logger.info(f"trying to post: {username}: {post.post_content}")
    success = await user_manager.post(username, post.post_content, password)
    if success:
        return JSONResponse(content={"message": "Posted!"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Failed to post!"}, status_code=500)


@app.post("/get_combined_timeline")
async def get_combined_timeline(request: Request, query: UsernamesQuery):
    logger.info(f"Received payload for combined timeline: {query}")
    user_data = get_current_user(request)
    current_user = query.current_user  # This is the current user's username
    if user_data['username'] != current_user:
        raise HTTPException(status_code=403, detail="Unauthorized action")
    password = user_data["password"]
    current_user_private_key = await user_manager.get_private_key(current_user, password)   
    symmetric_key = await user_manager.retrieve_symmetric_key(current_user, password)
    
    combined_timeline = []
    
    for username in query.usernames:
        if username != current_user:  # other users' posts
            friend_symmetric_key = await user_manager.retrieve_friends_symmetric_key(username, current_user, current_user_private_key)
            user_timeline = await user_manager.getTimeline(username, friend_symmetric_key)
        else:  # current user's posts
            user_timeline = await user_manager.getTimeline(username, password)
        combined_timeline.extend(user_timeline)
    sorted_combined_timeline = sorted(combined_timeline, key=lambda x: x['date_posted'], reverse=True)
    return JSONResponse(content={"timeline": sorted_combined_timeline}, status_code=200)






@app.post("/upload_profile_picture/{username}")
async def upload_profile_picture(request: Request, username: str, file: UploadFile = File(...)):
    session_id = request.cookies.get("session_id")
    user_data = secure_memory_manager.access(session_id)
    password = user_data["password"]
    symm_key = user_data["symmetric_key"]    
    profile= await user_manager.get_user_profile(username, password)

    if profile is None:
        return JSONResponse(content={"message": "Failed to retrieve user profile"}, status_code=400) 
      
           
    # Read the file content
    image_data = await file.read()

    # Save image data to DHT, encrypted with the user's symm key ofc
    image_key = f"{username}_profile_picture"
    image_data_encrypted = user_manager.encrypt_user_data(image_data, symm_key)
    await dht.save_to_dht(image_key, image_data_encrypted)


    profile['profile_picture_key'] = image_key
    profile_data = pickle.dumps(profile)
    encrypted_profile = user_manager.encrypt_user_data(profile_data, symm_key)
    await dht.save_to_dht(f"{username}_profile", encrypted_profile)

    return RedirectResponse(url=f"/profile/{username}", status_code=status.HTTP_302_FOUND)





        
@app.get("/get_profile_picture/{username}")
async def get_profile_picture(request: Request, username: str):
    session_id = request.cookies.get("session_id")
    logger.info(f"session id:{session_id}")
    user_data = secure_memory_manager.access(session_id)
    logger.info(f"user_data:{user_data}")
    password = user_data["password"]
    logger.info(f"using password:{password} with username: {username}")
    symkey = user_data["symmetric_key"]    
    logger.info(f"symmetric_key/get pic:{symkey}")
    profile_data = await user_manager.get_user_profile(username, password)

    
    if profile_data:
        if 'profile_picture_key' in profile_data:
            image_data = await dht.get(profile_data['profile_picture_key'])
            if image_data:
                ##it will be encrypted. first, we must decrypt with the symkey
                image_data_decoded = user_manager.decrypt_user_data(image_data, symkey)
                return StreamingResponse(io.BytesIO(image_data_decoded), media_type="image/jpeg")
            else:
                return JSONResponse(content={"message": "Image data not found"}, status_code=404)
    return JSONResponse(content={"message": "Profile picture not found"}, status_code=404)




@app.on_event("startup")
async def startup():
    global dht, user_manager
    web_port = int(sys.argv[1])
    dht_port = int(sys.argv[2])
    dht = DHTModel(local_port=dht_port, spec=lokispec)
    await dht.listen()
    if len(sys.argv) > 3:
        bootstrap_ip, bootstrap_port = sys.argv[3].split(":")
        await dht.bootstrap_to_node(bootstrap_ip, int(bootstrap_port))
    user_manager = UserManager(dht, lokispec)

@app.on_event("shutdown")
async def shutdown():
    await dht.close()

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py [web_port] [dht_port] [optional: bootstrap_ip:bootstrap_port]")
        sys.exit(1)
    
    web_port = int(sys.argv[1])
    uvicorn.run(app, host="0.0.0.0", port=web_port)
