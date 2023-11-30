import ctypes
import pickle
import logging

logger = logging.getLogger("uvicorn.error")

class SecureMemoryManager:
    _instance = None


    def __new__(cls, size):
        """
        Z-Specification:
        [SecureMemoryManager] ::= < secure_buffer: seq CHAR, size: N >

        :param size: Size of the secure buffer to create.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.size = size
            cls._instance.secure_buffer = ctypes.create_string_buffer(size)
            # Initialize with an empty dictionary
            empty_dict = pickle.dumps({})
            ctypes.memmove(cls._instance.secure_buffer, empty_dict, len(empty_dict))
        elif cls._instance.size != size:
            raise ValueError("A SecureMemoryManager instance already exists with a different size")
        
        return cls._instance


    def store(self, session_id, data):
        """
        Z-Specification:
        store!: seq CHAR x seq CHAR -> SecureMemoryManager
        pre: len(api_key + ":" + api_secret) <= size
        post: secure_buffer' = api_key + ":" + api_secret and len(secure_buffer') <= size

        :param data
        """
        # Access the existing dictionary
        existing_data = self.access()

        # Update the dictionary with the new data
        existing_data[session_id] = data

        # Serialize and store the updated dictionary
        bytes_data = pickle.dumps(existing_data)
        if len(bytes_data) > self.size:
            raise ValueError("Data is too large for the secure buffer")
        ctypes.memset(self.secure_buffer, 0, self.size)
        ctypes.memmove(self.secure_buffer, bytes_data, len(bytes_data))
        logger.info(f"stored in smm: key {session_id}, data:{data}")

    def access(self, session_id=None):
        """
        Z-Specification:
        access!: SecureMemoryManager -> seq CHAR x seq CHAR
        post: exists data! : seq CHAR . secure_buffer = data!

        :return: data
        """
        # Access the entire dictionary
        bytes_data = bytearray(self.secure_buffer)
        data = pickle.loads(bytes_data)
        logger.info(f"trying to access key:{session_id} which gives data:{data}")
        # Return specific session data if session_id is provided, else return the entire dictionary
        return data if session_id is None else data.get(session_id)

    def wipe(self, session_id=None):
        if session_id:
            # Remove specific session data
            data = self.access(session_id)
            if session_id in data:
                del data[session_id]
                self.store(session_id, data)
        else:
            # Wipe the entire buffer
            ctypes.memset(self.secure_buffer, 0, self.size)
