from PIL import Image
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import sys

def derive_key(password: str) -> bytes:
    """Derive a 32-byte key from password using SHA-256 (simple; use PBKDF2 for production)."""
    return hashlib.sha256(password.encode('utf-8')).digest()

def text_to_binary(text: str) -> str:
    """Convert text to binary string."""
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_bytes(binary_str: str) -> bytes:
    """Convert binary string to bytes."""
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

def encode_image(image_path: str, message: str, password: str, output_path: str):
    """
    Encrypt and encode a text message into an image using LSB steganography.
    
    Args:
    - image_path: Path to the cover image (PNG/BMP recommended).
    - message: Text message to hide.
    - password: Password for encryption.
    - output_path: Path to save the stego image.
    """
    # Derive key and create Fernet cipher
    key = derive_key(password)
    f = Fernet(base64.urlsafe_b64encode(key))
    
    # Encrypt the message
    message_bytes = message.encode('utf-8')
    ciphertext = f.encrypt(message_bytes)
    ciphertext_len = len(ciphertext)
    
    # Prepare binary payload: 32-bit length + binary of ciphertext + binary delimiter ('###')
    binary_length = format(ciphertext_len, '032b')
    binary_ciphertext = ''.join(format(byte, '08b') for byte in ciphertext)
    binary_delimiter = text_to_binary('###')  # 24 bits
    binary_message = binary_length + binary_ciphertext + binary_delimiter
    
    # Load the image
    img = Image.open(image_path)
    img = img.convert('RGB')  # Ensure RGB mode
    pixels = list(img.getdata())  # Get pixel list
    
    if len(binary_message) > len(pixels) * 3:  # 3 bits per pixel (R,G,B)
        raise ValueError("Encrypted message too long for image size. Need more pixels.")
    
    # Embed binary into LSB of pixels
    binary_index = 0
    new_pixels = []
    for pixel in pixels:
        r, g, b = pixel
        if binary_index < len(binary_message):
            # Embed in R
            r = (r & 0xFE) | int(binary_message[binary_index])
            binary_index += 1
        if binary_index < len(binary_message):
            # Embed in G
            g = (g & 0xFE) | int(binary_message[binary_index])
            binary_index += 1
        if binary_index < len(binary_message):
            # Embed in B
            b = (b & 0xFE) | int(binary_message[binary_index])
            binary_index += 1
        new_pixels.append((r, g, b))
    
    # Create new image with modified pixels
    new_img = Image.new('RGB', img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)
    print(f"Message encrypted and encoded. Saved to {output_path}")

def decode_image(image_path: str, password: str) -> str:
    """
    Decode and decrypt the hidden message from a stego image.
    
    Args:
    - image_path: Path to the stego image.
    - password: Password for decryption.
    
    Returns:
    - Extracted message (text).
    
    Raises:
    - ValueError: If delimiter mismatch or invalid length.
    - InvalidToken: If decryption fails (wrong password).
    """
    # Derive key and create Fernet cipher
    key = derive_key(password)
    f = Fernet(base64.urlsafe_b64encode(key))
    
    # Load the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = list(img.getdata())
    
    # Extract binary from LSB of all pixels (we'll use only what's needed)
    binary_extracted = ''
    for pixel in pixels:
        r, g, b = pixel
        binary_extracted += str(r & 1)  # LSB of R
        binary_extracted += str(g & 1)  # LSB of G
        binary_extracted += str(b & 1)  # LSB of B
    
    if len(binary_extracted) < 32 + 24:  # Min: length + delimiter
        raise ValueError("Image too small or no hidden data.")
    
    # Parse: first 32 bits = length
    binary_length = binary_extracted[:32]
    ciphertext_len = int(binary_length, 2)
    
    # Next: ciphertext bits
    start_cipher = 32
    end_cipher = start_cipher + (ciphertext_len * 8)
    binary_ciphertext = binary_extracted[start_cipher:end_cipher]
    
    if len(binary_ciphertext) != ciphertext_len * 8:
        raise ValueError("Invalid ciphertext length.")
    
    # Next: delimiter (24 bits for '###')
    delimiter_start = end_cipher
    binary_delimiter = binary_extracted[delimiter_start:delimiter_start + 24]
    expected_delimiter = text_to_binary('###')
    if binary_delimiter != expected_delimiter:
        raise ValueError("Delimiter mismatch. Data may be corrupted.")
    
    # Convert binary ciphertext to bytes and decrypt
    ciphertext_bytes = binary_to_bytes(binary_ciphertext)
    try:
        decrypted_bytes = f.decrypt(ciphertext_bytes)
        message = decrypted_bytes.decode('utf-8')
        return message
    except InvalidToken:
        raise InvalidToken("Decryption failed. Wrong password or corrupted data.")

# Example usage
if __name__ == "__main__":
    # Encoding example
    cover_image = "cover.png"  # Replace with your image path
    secret_message = "HELLO THIS IS THE SECRET MESSAGE"
    stego_image = "stego_encrypted.png"
    password = input("Enter password for encryption: ")  # Or hardcode for testing
    
    try:
        encode_image(cover_image, secret_message, password, stego_image)
        print("Encryption and encoding successful!")
        
        # Decoding example (use same password)
        decode_password = input("Enter password for decryption: ")
        extracted = decode_image(stego_image, decode_password)
        print(f"Extracted and decrypted message: {extracted}")
    except Exception as e:
        print(f"Error: {e}")
        if isinstance(e, InvalidToken):
            print("Tip: Double-check the password.")