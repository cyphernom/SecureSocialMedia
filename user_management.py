import os
import base64
import hashlib
import time
import sys
import asyncio
import logging
import concurrent.futures
import json
import binascii
import bcrypt
import secrets
import pickle
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

from kademlia.network import Server

logger = logging.getLogger("uvicorn.error")


class UserManager:
    def __init__(self, dht_module, spec):
        self.dht = dht_module
        self.lokispec = spec
        
    async def get_user_friends(self, username: str):
        # Fetch the friends list for the user from DHT
        friends_list_key = f"{username}_friends"
        friends_list_data = await self.dht.get(friends_list_key)
        if friends_list_data:
            return json.loads(friends_list_data)
        return []
        
    async def generate_and_store_symmetric_key(self, username: str, password: str):
        # Generate a symmetric key
        symmetric_key = os.urandom(32)  # For AES-256
        encrypted_symmetric_key, salt, iv = self.encrypt_data(symmetric_key, password)
        await self.dht.save_to_dht(f"{username}_symmetric_key", encrypted_symmetric_key)
        return symmetric_key        

    def encrypt_user_data(self, data: bytes, symmetric_key: bytes) -> str:
        fernet = Fernet(base64.urlsafe_b64encode(symmetric_key))
        return fernet.encrypt(data)

    def decrypt_user_data(self, encrypted_data: str, symmetric_key: bytes) -> bytes:
        fernet = Fernet(base64.urlsafe_b64encode(symmetric_key))
        return fernet.decrypt(encrypted_data)

    async def share_symmetric_key_with_friend(self, username: str, friend_username: str, symmetric_key: bytes):
        logger.info(f"trying to share your {username} symkey with {friend_username}")
        friend_public_key = await self.get_user_public_key(friend_username)
        logger.info(f"using friends pubkey:{friend_public_key}")
        encrypted_key_for_friend = self.encrypt_with_public_key(friend_public_key, symmetric_key)
        logger.info(f"encrypted symm key for friend:{encrypted_key_for_friend} saved in dht at {username}_symmetric_key_for_{friend_username}")
        await self.dht.save_to_dht(f"{username}_symmetric_key_for_{friend_username}", encrypted_key_for_friend)

    async def retrieve_friends_symmetric_key(self, username: str, friend_username: str, private_key):
        encrypted_key = await self.dht.get(f"{friend_username}_symmetric_key_for_{username}")
        if encrypted_key:
            return await decrypt_with_private_key(private_key, encrypted_key)
        return None

    async def send_friend_request(self, from_username: str, to_username: str, password: str):
        logger.info(f"sending friend request from {from_username} to {to_username}")
        pending_requests_key = f"{to_username}_pending_requests"
        logger.info(f"pending_requests_key:{pending_requests_key}")
        pending_requests_data = await self.dht.get(pending_requests_key)
    
        # Check if data is not None and decode it from bytes to string
        if pending_requests_data is not None:
            pending_requests = json.loads(pending_requests_data.decode('utf-8'))
        else:
            pending_requests = []
            
        logger.info(f"pending_requests:{pending_requests}")    

        if from_username not in pending_requests:
            pending_requests.append(from_username)
            #get your symm key
            your_symmetric_key = await self.retrieve_symmetric_key(from_username, password)
            logger.info(f"got your symmkey:{your_symmetric_key}")
            #encrypt it with your friends pub key and save:
            await self.share_symmetric_key_with_friend(from_username, to_username, your_symmetric_key)
            logger.info(f"Updated pending requests: {pending_requests}")           
            await self.dht.save_to_dht(pending_requests_key, json.dumps(pending_requests))

            return True
        return False


    async def accept_friend_request(self, username: str, friend_username: str, password):
        # Retrieve the pending requests
        pending_requests_key = f"{username}_pending_requests"
        pending_requests_data = await self.dht.get(pending_requests_key)
        user_private_key = await self.get_private_key(username, password)
        
        # Check if data is not None and decode it from bytes to string
        if pending_requests_data is not None:
            pending_requests = json.loads(pending_requests_data.decode('utf-8'))
        else:
            pending_requests = []
        
        your_symmetric_key = await self.retrieve_symmetric_key(username, password)
        logger.info(f"got symm key in usernames for you:{your_symmetric_key}")
            
        if friend_username in pending_requests:
            friend_symmetric_key = await self.retrieve_friends_symmetric_key(friend_username, username, user_private_key)
            logger.info(f"got friends symm key:{friend_symmetric_key}")
            await self.share_symmetric_key_with_friend(friend_username, username, friend_symmetric_key)


            # Add each user to the other's friend list
            await self.add_friend(username, friend_username)

            # Remove this request from the pending list
            pending_requests.remove(friend_username)
            await self.dht.save_to_dht(pending_requests_key, json.dumps(pending_requests))
            return True
        return False
    

    async def reject_friend_request(self, username: str, friend_username: str):
        # Remove this request from the pending list
        pending_requests_key = f"{username}_pending_requests"
        pending_requests_data = await self.dht.get(pending_requests_key)
        
        # Check if data is not None and decode it from bytes to string
        if pending_requests_data is not None:
            pending_requests = json.loads(pending_requests_data.decode('utf-8'))
        if friend_username in pending_requests:
            pending_requests.remove(friend_username)
            await self.dht.save_to_dht(pending_requests_key, json.dumps(pending_requests))
            return True
        return False

    async def add_friend(self, username: str, friend_username: str):
        # Retrieve current friends list for both users
        user_friends = await self.get_user_friends(username)
        friend_friends = await self.get_user_friends(friend_username)

        # Add each user to the other's friends list if not already present
        if friend_username not in user_friends:
            user_friends.append(friend_username)
            friends_list_key = f"{username}_friends"
            await self.dht.save_to_dht(friends_list_key, json.dumps(user_friends))

        if username not in friend_friends:
            friend_friends.append(username)
            friends_list_key = f"{friend_username}_friends"


            await self.dht.save_to_dht(friends_list_key, json.dumps(friend_friends))

        return True  # Indicate success



    async def get_user_public_key(self, username: str):
        # Fetch the public key string from DHT
        public_key_data = await self.dht.get(f"{username}_public_key")
        if public_key_data:
            try:
                # Load the public key from its serialized (PEM) format
                return serialization.load_pem_public_key(
                    public_key_data.encode('utf-8'),
                    backend=default_backend()
                )
            except Exception as e:
                logger.error(f"Failed to load public key for {username}: {e}")
        return None


    async def get_pending_friend_requests(self, username: str, password: str):
        pending_requests_key = f"{username}_pending_requests"
        logger.info(f"pending_requests_key: {pending_requests_key}")
        pending_requests_data = await self.dht.get(pending_requests_key)
        
        if pending_requests_data is None:
            logger.info(f"No data found for pending requests for {username}")
            return []
        elif pending_requests_data == "":
            logger.info(f"Pending requests data found but empty for {username}")
            return []

        try:
            return json.loads(pending_requests_data)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decoding error for {username}: {e}, data: {pending_requests_data}")
            return []  # or handle the error as needed



        
    async def create_user(self, username, password):
        # Generate user's RSA keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()

        # Serialize and store the public key
        public_key_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        await self.dht.save_to_dht(f"{username}_public_key", public_key_serialized)
        
        # Serialize the private key (without encryption)
        private_key_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Store the serialized private key directly in DHT
        await self.dht.save_to_dht(f"{username}_private_key", private_key_serialized)

        # Encrypt and store symmetric key
        symmetric_key = os.urandom(32)  # For AES-256
        encrypted_symmetric_key = self.encrypt_with_public_key(public_key, symmetric_key)
        await self.dht.save_to_dht(f"{username}_symmetric_key", encrypted_symmetric_key)

        profile = {"username":username}
        profile_data = pickle.dumps(profile)
        logger.info(f"profile_data:{profile_data}")
        profile_encrypted= self.encrypt_user_data(profile_data, symmetric_key)
        logger.info(f"profile_encrypted:{profile_encrypted}")
        # Hash the password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        await self.dht.save_to_dht(f"{username}_password", password_hash)
        
        await self.dht.save_to_dht(f"{username}_profile", profile_encrypted)

                        
        return public_key_serialized, private_key_serialized, symmetric_key                                        
        

    async def post(self, username, post_content, password):
        # Retrieve the user's symmetric key
        symmetric_key = await self.retrieve_symmetric_key(username, password)
        if symmetric_key is None:
            # Handle error: Symmetric key not found or failed to decrypt
            return False

        # Encrypt the post content
        encrypted_content = self.encrypt_user_data(post_content.encode(), symmetric_key)

        # Prepare the post data
        timeline_key = f"{username}_timeline"
        timeline_key_data = await self.dht.get(timeline_key)
        timeline = pickle.loads(timeline_key_data) if timeline_key_data is not None else []
        post_data = {
            "content": encrypted_content,  # Store encrypted content
            "date_posted": datetime.now().isoformat(),
            "username": username,
            "profile_picture_url": f"/get_profile_picture/{username}"
        }

        # Add to timeline and save
        timeline.append(post_data)
        serialized_timeline = pickle.dumps(timeline)
        return await self.dht.save_to_dht(timeline_key, serialized_timeline)

     

    async def getTimeline(self, username, password):
        timeline_key = f"{username}_timeline"
        timeline_key_data = await self.dht.get(timeline_key)

        if timeline_key_data is None:
            return []

        # Deserialize the timeline using pickle
        timeline = pickle.loads(timeline_key_data)

        # Retrieve the user's symmetric key
        symmetric_key = await self.retrieve_symmetric_key(username, password)
        if symmetric_key is None:
            return []

        # Decrypt each post in the timeline
        decrypted_timeline = []
        for post in timeline:
            try:
                decrypted_content = self.decrypt_user_data(post['content'], symmetric_key).decode('utf-8')
            except Exception as e:
                decrypted_content = f"Error decrypting post: {e}"

            decrypted_post = {
                "content": decrypted_content,
                "date_posted": post['date_posted'],
                "username": post['username'],
                "profile_picture_url": post['profile_picture_url']
            }
            decrypted_timeline.append(decrypted_post)

        # Sort the posts by date in descending order
        sorted_timeline = sorted(decrypted_timeline, key=lambda x: x['date_posted'], reverse=True)

        return sorted_timeline


        

        
    async def authenticate_user(self, username, password):
        # Fetch user's hashed password from DHT
        logger.info(f"username:{username} password:{password}")
        password_hash = await self.dht.get(f"{username}_password")
        logger.info(f"password_hash:{password_hash}")

        if password_hash is None or not bcrypt.checkpw(password.encode(), password_hash):
            logger.info("ser not found or password incorrect")
            return False, None  # User not found or password incorrect

        # Fetch encrypted private key and symmetric key
        encrypted_private_key = await self.dht.get(f"{username}_private_key")
        logger.info(f"encrypted private key:{encrypted_private_key}")
        encrypted_symmetric_key = await self.dht.get(f"{username}_symmetric_key")
        logger.info(f"encrypted_symmetric_key:{encrypted_symmetric_key}")
        if not encrypted_private_key or not encrypted_symmetric_key:
            return False, None  # Keys not found

        # Decrypt private key with user's password
        private_key =  await self.get_private_key(username, password)       
        logger.info(f"got key:{private_key}")
        symmetric_key = await self.retrieve_symmetric_key(username, password)
        logger.info(f"symmetric_key:{symmetric_key}")
        if not private_key or not symmetric_key:
            return False, None  # Key decryption failed

        return True, {"private_key": private_key, "symmetric_key": symmetric_key}



    async def get_user_profile(self, username, password):
        encrypted_data = await self.dht.get(f"{username}_profile")
        
        logger.info(f"get_user_profile/encrypted_data:{encrypted_data}")
        if not encrypted_data:
            return None

        symmetric_key = await self.retrieve_symmetric_key(username, password)
        logger.info(f"get_user_profile/symmetric_key:{symmetric_key}")        
        
        if not symmetric_key:
            logger.error("Symmetric key retrieval failed.")
            return None

        decrypted_data = self.decrypt_user_data(encrypted_data, symmetric_key)
        logger.info(f"get_user_profile/decrypted_data:{decrypted_data}")        

        try:
            decrypted = pickle.loads(decrypted_data)
            logger.info(f"profile pickle:{decrypted}")
            return decrypted
        except (pickle.PickleError, json.JSONDecodeError) as e:
            logger.error(f"Decoding error: {e}")
            return None

    async def set_user_profile(self, username, password, profile_data):
        try:
            # Retrieve the symmetric key for the user
            symmetric_key = await self.retrieve_symmetric_key(username, password)
            if not symmetric_key:
                logger.error("Symmetric key retrieval failed.")
                return False

            # Serialize the profile data
            serialized_data = pickle.dumps(profile_data)
            logger.info(f"set_user_profile/serialized_data:{serialized_data}")

            # Encrypt the serialized profile data using the symmetric key
            encrypted_data = self.encrypt_user_data(serialized_data, symmetric_key)
            logger.info(f"set_user_profile/encrypted_data:{encrypted_data}")

            # Save the encrypted data to the DHT
            await self.dht.save_to_dht(f"{username}_profile", encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error in set_user_profile: {e}")
            return False

    
    async def retrieve_symmetric_key(self, username, password):
        encrypted_key_data = await self.dht.get(f"{username}_symmetric_key")
        logger.info(f"encrypted_key_data:{encrypted_key_data}")
        if not encrypted_key_data:
            return None
        user_private_key = await self.get_private_key(username, password)
        logger.info(f"username:{username} password:{password} user_private_key:{user_private_key}") 
        return await self.decrypt_with_private_key(user_private_key, encrypted_key_data)


    def encrypt_data(self, data, password):
        try:
            # Ensure data is in bytes format
            if isinstance(data, str):
                data = data.encode()  # Convert to bytes if it's a string

            # Generate salt
            salt = os.urandom(16)

            # Create a KDF instance
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            # Derive the key
            key = kdf.derive(password.encode())

            # Generate IV for CFB mode
            iv = os.urandom(16)

            # Encrypt the data
            cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Return encoded encrypted data, salt, and IV
            return base64.b64encode(encrypted_data).decode('utf-8'), base64.b64encode(salt).decode('utf-8'), base64.b64encode(iv).decode('utf-8')
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            return None, None, None

    def decrypt_data(self, encrypted_data, password, salt, iv):
        encrypted_data = base64.b64decode(encrypted_data)
        salt = base64.b64decode(salt)
        iv = base64.b64decode(iv)

        # Create a KDF instance
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        # Derive the key
        key = kdf.derive(password.encode())

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        try:
            return data.decode('utf-8')  # Attempt to decode as UTF-8 string
        except UnicodeDecodeError:
            # Return raw bytes if decoding fails
            return data


    def encrypt_private_key(self, private_key, password):
        # Serialize private key to PEM format
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
        # Use the general encryption method
        return self.encrypt_data(private_key_bytes, password)

    async def decrypt_with_private_key(self, private_key: rsa.RSAPrivateKey, encrypted_data: str) -> bytes:
        try:
            logger.info(f"trying to decrypt: {encrypted_data} with private key:{private_key}")
            # Decode the encrypted data from Base64
            encrypted_data_bytes = encrypted_data#base64.b64decode(encrypted_data)
            logger.info(f"encrypted_data_bytes:{encrypted_data_bytes}")
            
            # Decrypt the data using the private key
            decrypted_data = private_key.decrypt(
                encrypted_data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return decrypted_data
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    async def get_private_key(self, username: str, password: str):
        # Fetch the serialized private key from DHT
        serialized_private_key = await self.dht.get(f"{username}_private_key")
        if not serialized_private_key:
            return None

        # Deserialize the private key
        try:
            private_key = serialization.load_pem_private_key(
                serialized_private_key,
                password=None,  # No password since it's not encrypted
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            logger.error(f"Error loading private key: {e}")
            return None




    def encrypt_with_public_key(self, public_key, data):
        if public_key is None or data is None:
            logger.error("Public key or data is None")
            return None
        try:
            encrypted_data = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_data
        except Exception as e:
            logger.error(f"Error during encryption: {e}")
            return None

       


