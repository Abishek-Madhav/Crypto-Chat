
import os
import sys
import time
import json
import base64
import hashlib
import datetime
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Directory to store messages
MESSAGE_DIR = "messages"
os.makedirs(MESSAGE_DIR, exist_ok=True)

# Generate a key from a password
def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Encrypt a message
def encrypt_message(message, password):
    key, salt = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message, salt

# Decrypt a message
def decrypt_message(encrypted_message, password, salt):
    key, _ = generate_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        return None

def timestamp_to_str(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

class TimeLockChat:
    def __init__(self, username):
        self.username = username
        self.shared_password = "shared_secret_key"  # In a real application, use a secure key exchange
        self.user_file = os.path.join(MESSAGE_DIR, f"{username}.json")
        
        # Initialize or load user file
        if os.path.exists(self.user_file):
            with open(self.user_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {
                "sent_messages": [],
                "received_messages": []
            }
            self._save_data()
    
    def _save_data(self):
        with open(self.user_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def send_message(self, recipient, message, unlock_time_minutes):
        """Send a time-locked message to recipient"""
        current_time = time.time()
        unlock_timestamp = current_time + (unlock_time_minutes * 60)
        
        # Encrypt the message
        encrypted_message, salt = encrypt_message(message, self.shared_password)
        
        # Create message object
        message_data = {
            "id": hashlib.md5(f"{self.username}_{time.time()}".encode()).hexdigest(),
            "from": self.username,
            "to": recipient,
            "encrypted_content": base64.b64encode(encrypted_message).decode(),
            "salt": base64.b64encode(salt).decode(),
            "sent_time": current_time,
            "unlock_time": unlock_timestamp,
            "message": message  # For simplicity, we're storing the original message too
        }
        
        # Save to sender's records
        self.data["sent_messages"].append(message_data)
        self._save_data()
        
        # Save to recipient's records
        recipient_file = os.path.join(MESSAGE_DIR, f"{recipient}.json")
        if os.path.exists(recipient_file):
            with open(recipient_file, 'r') as f:
                recipient_data = json.load(f)
        else:
            recipient_data = {
                "sent_messages": [],
                "received_messages": []
            }
        
        recipient_data["received_messages"].append(message_data)
        with open(recipient_file, 'w') as f:
            json.dump(recipient_data, f, indent=2)
        
        print(f"Message sent to {recipient}! Will be unlocked at {timestamp_to_str(unlock_timestamp)}")
    
    def check_messages(self):
        """Check for new messages and try to decrypt time-locked ones"""
        current_time = time.time()
        
        # Reload data to get fresh messages
        if os.path.exists(self.user_file):
            with open(self.user_file, 'r') as f:
                self.data = json.load(f)
        
        # Check received messages
        print("\n=== Your Messages ===")
        
        has_messages = False
        for idx, msg in enumerate(self.data["received_messages"]):
            has_messages = True
            unlocked = current_time >= msg["unlock_time"]
            
            print(f"\nMessage {idx+1}:")
            print(f"From: {msg['from']}")
            print(f"Sent: {timestamp_to_str(msg['sent_time'])}")
            print(f"Unlock time: {timestamp_to_str(msg['unlock_time'])}")
            
            if unlocked:
                encrypted_content = base64.b64decode(msg["encrypted_content"])
                salt = base64.b64decode(msg["salt"])
                decrypted = decrypt_message(encrypted_content, self.shared_password, salt)
                
                if decrypted:
                    print(f"Status: 🔓 UNLOCKED")
                    print(f"Content: {decrypted}")
                else:
                    print(f"Status: ⚠️ DECRYPTION ERROR")
            else:
                time_left = msg["unlock_time"] - current_time
                minutes_left = int(time_left / 60)
                seconds_left = int(time_left % 60)
                print(f"Status: 🔒 LOCKED (Unlocks in {minutes_left}m {seconds_left}s)")
        
        if not has_messages:
            print("No messages received yet.")
    
    def run_shell(self):
        """Run an interactive shell for the user"""
        print(f"\n==== Time-Lock Crypto Chat - User: {self.username} ====")
        print("Type 'help' for available commands")
        
        while True:
            command = input(f"\n{self.username}> ").strip()
            
            if command == "exit":
                print("Goodbye!")
                break
                
            elif command == "help":
                print("\nAvailable commands:")
                print("  send <recipient> <unlock_minutes> - Start sending a message")
                print("  check - Check your messages")
                print("  exit - Exit the program")
                print("  help - Show this help message")
                
            elif command.startswith("send"):
                parts = command.split(maxsplit=3)
                if len(parts) < 3:
                    print("Usage: send <recipient> <unlock_minutes>")
                    continue
                    
                recipient = parts[1]
                try:
                    unlock_minutes = float(parts[2])
                except ValueError:
                    print("Error: unlock_minutes must be a number")
                    continue
                
                print(f"Enter your message to {recipient} (press Enter twice to send):")
                lines = []
                while True:
                    line = input()
                    if not line and lines:  # Empty line and we have content
                        break
                    lines.append(line)
                
                message = "\n".join(lines)
                if message:
                    self.send_message(recipient, message, unlock_minutes)
                
            elif command == "check":
                self.check_messages()
                
            else:
                print("Unknown command. Type 'help' for available commands.")

def main():
    parser = argparse.ArgumentParser(description="Time-Lock Crypto Chat Simulation")
    parser.add_argument("username", help="Your username")
    args = parser.parse_args()
    
    chat = TimeLockChat(args.username)
    chat.run_shell()

if __name__ == "__main__":
    main()