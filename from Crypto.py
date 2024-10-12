from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt a message
def encrypt(message, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ct
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None, None

# Function to decrypt a message
def decrypt(iv, ct, key):
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return None

# Main function to handle input/output
def main():
    key = get_random_bytes(16)  # AES key must be 16, 24, or 32 bytes long

    print("Choose an option:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    choice = input("Enter your choice (1 or 2): ")

    if choice == "1":
        message = input("Enter the message to encrypt: ")
        iv, ct = encrypt(message, key)
        if iv and ct:
            print(f"\nEncryption successful!")
            print(f"IV (Initialization Vector): {iv}")
            print(f"Ciphertext (Encrypted message): {ct}")
            print(f"Your key (store it safely): {base64.b64encode(key).decode('utf-8')}\n")
        else:
            print("Encryption failed.")

    elif choice == "2":
        iv = input("Enter the IV: ")
        ct = input("Enter the ciphertext: ")
        key_input = input("Enter the key: ")
        try:
            key = base64.b64decode(key_input)  # Decode the key from base64
        except Exception as e:
            print(f"Key decoding failed: {e}")
            return
        
        decrypted_message = decrypt(iv, ct, key)
        if decrypted_message:
            print(f"\nDecryption successful! Decrypted message: {decrypted_message}\n")
        else:
            print("Decryption failed.")
    else:
        print("Invalid choice! Please select 1 or 2.")

if __name__ == "__main__":
    main()
