import os
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def send_encrypted(secret_key, channel, message):
    '''
    Encrypt the message after creating a cipher,
    and send it over the channel passed as parameter.
    '''
    try:
        # 1. Generate a random initialization vector (IV)
        iv = get_random_bytes(AES.block_size)

        # 2. Create an AES cipher object in CBC mode
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)

        # 3. Pad the message to be a multiple of the block size
        padded_message = pad(message.encode('utf-8'), AES.block_size)

        # 4. Encrypt the padded message
        ciphertext = cipher.encrypt(padded_message)

        # 5. Create a timestamp
        timestamp = str(int(time.time())).encode('utf-8')

        # 6. Calculate an HMAC to prevent tampering and replay attacks
        hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
        hmac_obj.update(iv)
        hmac_obj.update(ciphertext)
        hmac_obj.update(timestamp)
        hmac_value = hmac_obj.digest()

        # 7. Combine IV, ciphertext, timestamp, and HMAC for transmission
        #    Important:  Encode the IV, ciphertext, timestamp, and HMAC in a way that
        #    the receiver can reliably parse them.  Here, we use a simple concatenation.
        #    A more robust approach would be to use a serialization format like JSON or Protocol Buffers.
        #    However, for simplicity, we'll stick with concatenation.  The receiver *must* know
        #    the lengths of each component.
        
        # Construct the message: IV (16 bytes) + Ciphertext + Timestamp + HMAC (32 bytes)
        # The receiver needs to know these lengths to parse the message correctly.
        message_to_send = iv + ciphertext + timestamp + hmac_value

        # 8. Send the combined message over the channel
        channel.send(message_to_send)  # Assuming channel.send() exists

    except Exception as e:
        print(f"Error during encryption or sending: {e}")
        # Handle the error appropriately (e.g., log it, raise an exception)
        raise

def receive_encrypted(secret_key, channel):
    '''
    Receive and decrypt the message from the channel.
    '''
    try:
        received_message = channel.receive() # Assuming channel.receive() exists

        # 1. Extract the IV, ciphertext, timestamp, and HMAC
        iv = received_message[:AES.block_size]
        hmac_length = 32  # SHA256 HMAC is 32 bytes
        timestamp_length = len(str(int(time.time())).encode('utf-8')) # Length of timestamp
        ciphertext = received_message[AES.block_size:-timestamp_length-hmac_length]
        timestamp = received_message[-timestamp_length-hmac_length:-hmac_length]
        hmac_received = received_message[-hmac_length:]

        # 2. Verify the HMAC
        hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
        hmac_obj.update(iv)
        hmac_obj.update(ciphertext)
        hmac_obj.update(timestamp)
        hmac_calculated = hmac_obj.digest()

        if not hmac.compare_digest(hmac_received, hmac_calculated):
            raise ValueError("HMAC verification failed!  Possible tampering or incorrect key.")

        # 3. Check the timestamp to prevent replay attacks
        current_time = int(time.time())
        message_time = int(timestamp.decode('utf-8'))
        time_difference = current_time - message_time

        # Define a reasonable time window (e.g., 5 seconds)
        if time_difference > 5:
            raise ValueError("Message is too old!  Possible replay attack.")

        # 4. Create an AES cipher object in CBC mode
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)

        # 5. Decrypt the ciphertext
        padded_message = cipher.decrypt(ciphertext)

        # 6. Unpad the message
        unpadded_message = unpad(padded_message, AES.block_size)

        # 7. Decode the message
        message = unpadded_message.decode('utf-8')

        return message

    except Exception as e:
        print(f"Error during decryption or receiving: {e}")
        # Handle the error appropriately (e.g., log it, raise an exception)
        raise

