import asyncio
from kademlia.network import Server
import json
import uuid
import base64
import hashlib
import logging

logger = logging.getLogger("uvicorn.error")

class DHTModel:
    def __init__(self, local_port, spec):
        self.dht = Server()
        self.local_port = local_port
        self.lokispec = spec

    async def listen(self):
        try:
            await self.dht.listen(self.local_port)
            logger.info(f"DHT server listening on port {self.local_port}")
        except Exception as e:
            logger.error(f"Error starting DHT server: {e}")
            raise

    async def save_to_dht(self, key, value):
        hashed_key = self.hash_key(key)
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            elif isinstance(value, (int, float, bool)):
                value = str(value)

            return await self.save_large_data(hashed_key, value)
        except Exception as e:
            logger.error(f"Error saving data to DHT for key {key}: {e}")
            return False

    async def save_large_data(self, key, data):
        try:
            chunks = self.chunk_data(data)
            next_chunk_key = None
            kounter = 0
            for i in reversed(range(len(chunks))):
                if i > kounter:
                    kounter = i
                logger.info(f"storing chunks: {kounter-i}/{kounter}")
                chunk = chunks[i]
                chunk_key = f"{uuid.uuid4()}"
                chunk_payload = {
                    "data": base64.b64encode(chunk).decode('utf-8'),
                    "next": next_chunk_key,
                    "index": i,
                    "is_end": i == len(chunks) - 1
                }
                chunk_payload_json = json.dumps(chunk_payload)
                await self.dht.set(chunk_key, chunk_payload_json)
                next_chunk_key = chunk_key

            await self.dht.set(key, next_chunk_key)
            return True
        except Exception as e:
            logger.error(f"Error saving large data to DHT for key {key}: {e}")
            return False

    def chunk_data(self, data, chunk_size=1):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    async def retrieve_large_data(self, entry_point_key):
        chunks = []
        next_chunk_key = entry_point_key

        while next_chunk_key:
            try:
                chunk_payload_json = await self.dht.get(next_chunk_key)
                chunk_payload = json.loads(chunk_payload_json)
                chunks.append(base64.b64decode(chunk_payload["data"]))
                next_chunk_key = chunk_payload["next"] if not chunk_payload["is_end"] else None
            except Exception as e:
                logger.error(f"Error retrieving large data chunk: {e}")
                return None

        return b''.join(chunks)

    async def get(self, key):
        hashed_key = self.hash_key(key)
        try:
            entry_point_key = await self.dht.get(hashed_key)
            if entry_point_key is None:
                return None

            try:
                return await self.retrieve_large_data(entry_point_key)
            except json.JSONDecodeError:
                return entry_point_key
        except Exception as e:
            logger.error(f"Error retrieving data for key {key}: {e}")
            return None

    def proof_of_work(self, data, difficulty):
        nonce = 0
        while True:
            combined_data = f"{data}{nonce}".encode()
            result = hashlib.sha256(combined_data).hexdigest()
            if result[:difficulty] == '0' * difficulty:
                return nonce
            nonce += 1

    async def bootstrap_to_node(self, bootstrap_ip, bootstrap_port, retries=4):
        try:
            known_nodes = [(bootstrap_ip, bootstrap_port)]
            for i in range(retries):
                try:
                    await self.dht.bootstrap(known_nodes)
                    break
                except Exception as e:
                    if i < retries - 1:
                        continue
                    else:
                        raise e
        except Exception as e:
            logger.error(f"Error bootstrapping DHT node: {e}")
            raise

    async def close(self):
        try:
            self.dht.close()
        except Exception as e:
            logger.error(f"Error closing DHT: {e}")

    def hash_key(self, key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()
