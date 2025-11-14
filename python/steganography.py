# python/steganography.py - FIXED VERSION
import sys
import json
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import io

# ✅ FIX: Redirect ALL prints to stderr EXCEPT final JSON
def log(message):
    """Safe logging to stderr"""
    print(message, file=sys.stderr, flush=True)

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0.0
    flat_data = np.array(data).flatten()
    hist, _ = np.histogram(flat_data, bins=256, range=(0, 256))
    hist = hist[hist > 0]
    hist = hist / hist.sum()
    entropy = -np.sum(hist * np.log2(hist))
    return float(entropy)

def simple_scramble(image_array):
    """Simple chaotic scrambling"""
    flat = image_array.flatten()
    np.random.seed(42)
    indices = np.random.permutation(len(flat))
    scrambled = flat[indices]
    return scrambled.reshape(image_array.shape), indices

def simple_unscramble(scrambled_array, indices):
    """Reverse scrambling"""
    flat = scrambled_array.flatten()
    original = np.zeros_like(flat)
    original[indices] = flat
    return original.reshape(scrambled_array.shape)

def embed_lsb_fast(cover_image, secret_data):
    """FAST LSB embedding using NumPy vectorization"""
    try:
        # Convert to RGB
        if cover_image.mode != 'RGB':
            cover_image = cover_image.convert('RGB')
        
        cover_array = np.array(cover_image, dtype=np.uint8)
        log(f'Cover array shape: {cover_array.shape}')
        
        # Convert data to bit array
        data_bits = np.unpackbits(np.frombuffer(secret_data, dtype=np.uint8))
        data_length = len(data_bits)
        
        # Create length header (32 bits)
        length_bits = np.array([int(b) for b in format(data_length, '032b')], dtype=np.uint8)
        
        # Combine header + data
        all_bits = np.concatenate([length_bits, data_bits])
        
        log(f'Total bits to embed: {len(all_bits)}')
        
        # Check capacity
        flat_cover = cover_array.flatten()
        capacity = len(flat_cover)
        
        if len(all_bits) > capacity:
            raise ValueError(f'Cover too small: need {len(all_bits)} bits, have {capacity}')
        
        log(f'Flattened cover size: {len(flat_cover)}')
        
        # FAST EMBEDDING
        log(f'Embedding {len(all_bits)} bits...')
        flat_cover[:len(all_bits)] = (flat_cover[:len(all_bits)] & 0xFE) | all_bits
        
        log('Embedding complete, reshaping...')
        
        # Reshape and create image
        stego_array = flat_cover.reshape(cover_array.shape)
        stego_image = Image.fromarray(stego_array, mode='RGB')
        
        log('Stego image created successfully')
        
        return stego_image
        
    except Exception as e:
        log(f'LSB embedding error: {str(e)}')
        raise

def extract_lsb_fast(stego_image):
    """FAST LSB extraction using NumPy"""
    try:
        if stego_image.mode != 'RGB':
            stego_image = stego_image.convert('RGB')
        
        stego_array = np.array(stego_image, dtype=np.uint8).flatten()
        
        log(f'Extracting from {len(stego_array)} pixels')
        
        # Extract length (first 32 bits)
        length_bits = stego_array[:32] & 1
        data_length = int(''.join(str(b) for b in length_bits), 2)
        
        log(f'Data length: {data_length} bits')
        
        if data_length <= 0 or data_length > len(stego_array) - 32:
            raise ValueError(f'Invalid data length: {data_length}')
        
        # Extract data bits
        data_bits = stego_array[32:32+data_length] & 1
        
        log(f'Extracted {len(data_bits)} bits, converting to bytes...')
        
        # Convert bits to bytes
        remainder = len(data_bits) % 8
        if remainder != 0:
            data_bits = np.concatenate([data_bits, np.zeros(8 - remainder, dtype=np.uint8)])
        
        secret_bytes = np.packbits(data_bits).tobytes()
        
        log(f'Converted to {len(secret_bytes)} bytes')
        
        return secret_bytes
        
    except Exception as e:
        log(f'LSB extraction error: {str(e)}')
        raise

def encrypt_with_steganography(secret_path, cover_path, key, chaotic_map='logistic'):
    """Triple-layer encryption with FAST embedding"""
    try:
        log('Starting steganography encryption...')
        
        # Load secret
        secret_img = Image.open(secret_path)
        log(f'Secret image loaded: {secret_img.size}, mode: {secret_img.mode}')
        
        if secret_img.mode not in ['RGB', 'L']:
            secret_img = secret_img.convert('RGB')
        
        secret_array = np.array(secret_img)
        original_entropy = calculate_entropy(secret_array)
        
        # Metadata
        metadata = {
            'mode': secret_img.mode,
            'shape': list(secret_array.shape),
            'dtype': str(secret_array.dtype)
        }
        
        log(f'Secret image: {secret_array.shape}, mode: {secret_img.mode}')
        
        # Scramble
        scrambled, _ = simple_scramble(secret_array)
        secret_bytes = scrambled.tobytes()
        log(f'Scrambled size: {len(secret_bytes)} bytes')
        
        # Metadata
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Encrypt
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        iv = cipher.iv
        
        padded_data = pad(secret_bytes, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        log(f'Encrypted size: {len(encrypted_data)} bytes')
        
        encrypted_entropy = calculate_entropy(np.frombuffer(encrypted_data, dtype=np.uint8))
        
        # Combine
        full_data = (
            metadata_length.to_bytes(4, byteorder='big') +
            metadata_json +
            iv +
            encrypted_data
        )
        
        log(f'Total data to embed: {len(full_data)} bytes')
        
        # Load cover
        cover_img = Image.open(cover_path)
        log(f'Cover image loaded: {cover_img.size}, mode: {cover_img.mode}')
        
        if cover_img.mode != 'RGB':
            cover_img = cover_img.convert('RGB')
        
        # Check capacity
        cover_size = cover_img.size[0] * cover_img.size[1] * 3
        required_bits = len(full_data) * 8 + 32
        
        log(f'Cover capacity: {cover_size} bits, Required: {required_bits} bits')
        
        if required_bits > cover_size:
            return {
                'success': False,
                'error': f'Cover too small: need {required_bits} bits, have {cover_size} bits'
            }
        
        # FAST EMBED
        log('Starting FAST LSB embedding...')
        stego_img = embed_lsb_fast(cover_img, full_data)
        
        # Save
        output_dir = os.path.dirname(cover_path)
        if not output_dir:
            output_dir = '/tmp/uploads/stego'
        
        # Ensure directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        base_name = os.path.splitext(os.path.basename(cover_path))[0]
        stego_path = os.path.join(output_dir, f"{base_name}_stego.png")
        
        log(f'Saving stego image to: {stego_path}')
        stego_img.save(stego_path, 'PNG')
        
        log(f'✅ Stego image saved successfully')
        
        # ✅ Return JSON result
        return {
            'success': True,
            'stego_path': stego_path,
            'message': 'Triple-layer encryption successful',
            'metrics': {
                'entropy': {
                    'original': round(original_entropy, 4),
                    'encrypted': round(encrypted_entropy, 4)
                },
                'size': os.path.getsize(stego_path)
            }
        }
        
    except Exception as e:
        log(f'❌ Encryption failed: {str(e)}')
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {
            'success': False,
            'error': str(e)
        }

def decrypt_from_steganography(stego_path, key):
    """Triple-layer decryption with FAST extraction"""
    try:
        log('Starting steganography decryption...')
        
        # Load stego
        stego_img = Image.open(stego_path)
        log(f'Stego image loaded: {stego_img.size}')
        
        # FAST EXTRACT
        extracted_data = extract_lsb_fast(stego_img)
        log(f'Extracted {len(extracted_data)} bytes')
        
        # Parse metadata
        metadata_length = int.from_bytes(extracted_data[:4], byteorder='big')
        log(f'Metadata length: {metadata_length}')
        
        metadata_json = extracted_data[4:4+metadata_length]
        metadata = json.loads(metadata_json.decode('utf-8'))
        log(f'Metadata: {metadata}')
        
        # Get IV and encrypted
        iv_start = 4 + metadata_length
        iv = extracted_data[iv_start:iv_start+16]
        encrypted_data = extracted_data[iv_start+16:]
        
        log(f'Encrypted data size: {len(encrypted_data)} bytes')
        
        # Decrypt
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            log(f'Decrypted data size: {len(decrypted_data)} bytes')
        except:
            return {'success': False, 'error': 'Invalid key or corrupted data'}
        
        # Reconstruct
        shape = tuple(metadata['shape'])
        dtype = np.dtype(metadata['dtype'])
        img_array = np.frombuffer(decrypted_data, dtype=dtype).reshape(shape)
        
        # Unscramble
        np.random.seed(42)
        indices = np.random.permutation(img_array.size)
        img_array = simple_unscramble(img_array, indices)
        
        # Save
        img = Image.fromarray(img_array.astype(np.uint8), mode=metadata['mode'])
        output_dir = os.path.dirname(stego_path)
        if not output_dir:
            output_dir = '/tmp/uploads/decrypted'
        
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"extracted_{os.path.basename(stego_path)}")
        img.save(output_path)
        
        log(f'✅ Extracted image saved: {output_path}')
        
        return {
            'success': True,
            'decrypted_path': output_path,
            'message': 'Extraction successful'
        }
        
    except Exception as e:
        log(f'❌ Decryption failed: {str(e)}')
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

def main():
    """Main entry point - prints ONLY JSON to stdout"""
    try:
        if len(sys.argv) < 2:
            result = {'success': False, 'error': 'No command specified'}
        elif sys.argv[1] == 'encrypt' and len(sys.argv) >= 5:
            result = encrypt_with_steganography(
                sys.argv[2], 
                sys.argv[3], 
                sys.argv[4],
                sys.argv[5] if len(sys.argv) > 5 else 'logistic'
            )
        elif sys.argv[1] == 'decrypt' and len(sys.argv) >= 4:
            result = decrypt_from_steganography(sys.argv[2], sys.argv[3])
        else:
            result = {'success': False, 'error': 'Invalid command or arguments'}
        
        # ✅ CRITICAL: Print ONLY JSON to stdout (no extra text!)
        print(json.dumps(result), flush=True)
        
    except Exception as e:
        log(f'Fatal error in main: {str(e)}')
        error_result = {'success': False, 'error': str(e)}
        print(json.dumps(error_result), flush=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
