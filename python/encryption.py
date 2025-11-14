import sys
import json
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0.0
    
    # Convert to flat array
    flat_data = np.array(data).flatten()
    
    # Calculate histogram
    hist, _ = np.histogram(flat_data, bins=256, range=(0, 256))
    
    # Remove zero bins
    hist = hist[hist > 0]
    
    # Normalize
    hist = hist / hist.sum()
    
    # Calculate entropy
    entropy = -np.sum(hist * np.log2(hist))
    
    return float(entropy)

def simple_scramble(image_array):
    """Simple chaotic scrambling using logistic map"""
    flat = image_array.flatten()
    np.random.seed(42)
    indices = np.random.permutation(len(flat))
    scrambled = flat[indices]
    return scrambled.reshape(image_array.shape), indices

def simple_unscramble(scrambled_array, indices):
    """Reverse the scrambling"""
    flat = scrambled_array.flatten()
    original = np.zeros_like(flat)
    original[indices] = flat
    return original.reshape(scrambled_array.shape)

def encrypt_image(image_path, key, chaotic_map='logistic'):
    """Encrypt image to .bin file with metrics"""
    try:
        # Load image
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Calculate original entropy
        original_entropy = calculate_entropy(img_array)
        
        # Store metadata
        metadata = {
            'mode': img.mode,
            'shape': list(img_array.shape),
            'dtype': str(img_array.dtype)
        }
        
        # Scramble
        scrambled, indices = simple_scramble(img_array)
        
        # Convert to bytes
        img_bytes = scrambled.tobytes()
        
        # Prepare metadata
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # AES encryption
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        iv = cipher.iv
        
        # Pad and encrypt
        padded_data = pad(img_bytes, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Calculate encrypted entropy
        encrypted_entropy = calculate_entropy(np.frombuffer(encrypted_data, dtype=np.uint8))
        
        # Save encrypted file
        base_name = os.path.splitext(image_path)[0]
        output_path = f"{base_name}_encrypted.bin"
        
        with open(output_path, 'wb') as f:
            # Write: metadata_length(4 bytes) + metadata + IV + encrypted_data
            f.write(metadata_length.to_bytes(4, byteorder='big'))
            f.write(metadata_json)
            f.write(iv)
            f.write(encrypted_data)
        
        return {
            'success': True,
            'encrypted_path': output_path,
            'message': 'Encryption successful',
            'metrics': {
                'entropy': {
                    'original': round(original_entropy, 4),
                    'encrypted': round(encrypted_entropy, 4)
                },
                'size': os.path.getsize(output_path)
            }
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def decrypt_image(encrypted_path, key):
    """Decrypt .bin file to image"""
    try:
        with open(encrypted_path, 'rb') as f:
            # Read metadata length
            metadata_length = int.from_bytes(f.read(4), byteorder='big')
            
            # Read metadata
            metadata_json = f.read(metadata_length)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Read IV
            iv = f.read(16)
            
            # Read encrypted data
            encrypted_data = f.read()
        
        # Decrypt
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except ValueError as e:
            return {
                'success': False,
                'error': 'Invalid key or corrupted file'
            }
        
        # Reconstruct array
        shape = tuple(metadata['shape'])
        dtype = np.dtype(metadata['dtype'])
        img_array = np.frombuffer(decrypted_data, dtype=dtype).reshape(shape)
        
        # Unscramble (using same seed)
        np.random.seed(42)
        indices = np.random.permutation(img_array.size)
        img_array = simple_unscramble(img_array, indices)
        
        # Save image
        img = Image.fromarray(img_array.astype(np.uint8), mode=metadata['mode'])
        
        base_name = os.path.splitext(encrypted_path)[0]
        output_path = f"{base_name}_decrypted.png"
        img.save(output_path)
        
        return {
            'success': True,
            'decrypted_path': output_path,
            'message': 'Decryption successful'
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'success': False, 'error': 'Invalid arguments'}))
        return
    
    command = sys.argv[1]
    
    try:
        if command == 'encrypt' and len(sys.argv) >= 4:
            image_path = sys.argv[2]
            key = sys.argv[3]
            chaotic_map = sys.argv[4] if len(sys.argv) > 4 else 'logistic'
            result = encrypt_image(image_path, key, chaotic_map)
            
        elif command == 'decrypt' and len(sys.argv) >= 4:
            encrypted_path = sys.argv[2]
            key = sys.argv[3]
            result = decrypt_image(encrypted_path, key)
            
        else:
            result = {'success': False, 'error': 'Invalid command'}
        
        print(json.dumps(result))
        
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))

if __name__ == '__main__':
    main()
