import sys
import json
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

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
        print(f'Cover array shape: {cover_array.shape}', file=sys.stderr)
        
        # Convert data to bit array (much faster than string concatenation)
        data_bits = np.unpackbits(np.frombuffer(secret_data, dtype=np.uint8))
        data_length = len(data_bits)
        
        # Create length header (32 bits)
        length_bits = np.array([int(b) for b in format(data_length, '032b')], dtype=np.uint8)
        
        # Combine header + data
        all_bits = np.concatenate([length_bits, data_bits])
        
        print(f'Total bits to embed: {len(all_bits)}', file=sys.stderr)
        
        # Check capacity
        flat_cover = cover_array.flatten()
        capacity = len(flat_cover)
        
        if len(all_bits) > capacity:
            raise ValueError(f'Cover too small: need {len(all_bits)} bits, have {capacity}')
        
        print(f'Flattened cover size: {len(flat_cover)}', file=sys.stderr)
        
        # FAST EMBEDDING: Clear LSB and set new bits (vectorized)
        print(f'Embedding {len(all_bits)} bits...', file=sys.stderr)
        flat_cover[:len(all_bits)] = (flat_cover[:len(all_bits)] & 0xFE) | all_bits
        
        print(f'Embedding complete, reshaping...', file=sys.stderr)
        
        # Reshape and create image
        stego_array = flat_cover.reshape(cover_array.shape)
        stego_image = Image.fromarray(stego_array, mode='RGB')
        
        print(f'Stego image created successfully', file=sys.stderr)
        
        return stego_image
        
    except Exception as e:
        print(f'LSB embedding error: {str(e)}', file=sys.stderr)
        raise

def extract_lsb_fast(stego_image):
    """FAST LSB extraction using NumPy"""
    try:
        if stego_image.mode != 'RGB':
            stego_image = stego_image.convert('RGB')
        
        stego_array = np.array(stego_image, dtype=np.uint8).flatten()
        
        print(f'Extracting from {len(stego_array)} pixels', file=sys.stderr)
        
        # Extract length (first 32 bits)
        length_bits = stego_array[:32] & 1
        data_length = int(''.join(str(b) for b in length_bits), 2)
        
        print(f'Data length: {data_length} bits', file=sys.stderr)
        
        if data_length <= 0 or data_length > len(stego_array) - 32:
            raise ValueError(f'Invalid data length: {data_length}')
        
        # Extract data bits (vectorized)
        data_bits = stego_array[32:32+data_length] & 1
        
        print(f'Extracted {len(data_bits)} bits, converting to bytes...', file=sys.stderr)
        
        # Convert bits to bytes (NumPy packbits is MUCH faster)
        # Pad to multiple of 8
        remainder = len(data_bits) % 8
        if remainder != 0:
            data_bits = np.concatenate([data_bits, np.zeros(8 - remainder, dtype=np.uint8)])
        
        secret_bytes = np.packbits(data_bits).tobytes()
        
        print(f'Converted to {len(secret_bytes)} bytes', file=sys.stderr)
        
        return secret_bytes
        
    except Exception as e:
        print(f'LSB extraction error: {str(e)}', file=sys.stderr)
        raise

def encrypt_with_steganography(secret_path, cover_path, key, chaotic_map='logistic'):
    """Triple-layer encryption with FAST embedding"""
    try:
        print(f'Starting steganography encryption...', file=sys.stderr)
        
        # Load secret
        secret_img = Image.open(secret_path)
        print(f'Secret image loaded: {secret_img.size}, mode: {secret_img.mode}', file=sys.stderr)
        
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
        
        print(f'Secret image: {secret_array.shape}, mode: {secret_img.mode}', file=sys.stderr)
        
        # Scramble
        scrambled, _ = simple_scramble(secret_array)
        secret_bytes = scrambled.tobytes()
        print(f'Scrambled size: {len(secret_bytes)} bytes', file=sys.stderr)
        
        # Metadata
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Encrypt
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        iv = cipher.iv
        
        padded_data = pad(secret_bytes, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        print(f'Encrypted size: {len(encrypted_data)} bytes', file=sys.stderr)
        
        encrypted_entropy = calculate_entropy(np.frombuffer(encrypted_data, dtype=np.uint8))
        
        # Combine
        full_data = (
            metadata_length.to_bytes(4, byteorder='big') +
            metadata_json +
            iv +
            encrypted_data
        )
        
        print(f'Total data to embed: {len(full_data)} bytes', file=sys.stderr)
        
        # Load cover
        cover_img = Image.open(cover_path)
        print(f'Cover image loaded: {cover_img.size}, mode: {cover_img.mode}', file=sys.stderr)
        
        if cover_img.mode != 'RGB':
            cover_img = cover_img.convert('RGB')
        
        # Check capacity
        cover_size = cover_img.size[0] * cover_img.size[1] * 3
        required_bits = len(full_data) * 8 + 32
        
        print(f'Cover capacity: {cover_size} bits, Required: {required_bits} bits', file=sys.stderr)
        
        if required_bits > cover_size:
            return {
                'success': False,
                'error': f'Cover too small: need {required_bits} bits, have {cover_size} bits'
            }
        
        # FAST EMBED
        print(f'Starting FAST LSB embedding...', file=sys.stderr)
        stego_img = embed_lsb_fast(cover_img, full_data)
        
        # Save
        output_dir = os.path.dirname(cover_path)
        base_name = os.path.splitext(os.path.basename(cover_path))[0]
        stego_path = os.path.join(output_dir, f"{base_name}_stego.png")
        
        print(f'Saving stego image...', file=sys.stderr)
        stego_img.save(stego_path, 'PNG')
        
        print(f'✅ Stego image saved: {stego_path}', file=sys.stderr)
        
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
        print(f'❌ Encryption failed: {str(e)}', file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {
            'success': False,
            'error': str(e)
        }

def decrypt_from_steganography(stego_path, key):
    """Triple-layer decryption with FAST extraction"""
    try:
        print(f'Starting steganography decryption...', file=sys.stderr)
        
        # Load stego
        stego_img = Image.open(stego_path)
        print(f'Stego image loaded: {stego_img.size}', file=sys.stderr)
        
        # FAST EXTRACT
        extracted_data = extract_lsb_fast(stego_img)
        print(f'Extracted {len(extracted_data)} bytes', file=sys.stderr)
        
        # Parse metadata
        metadata_length = int.from_bytes(extracted_data[:4], byteorder='big')
        print(f'Metadata length: {metadata_length}', file=sys.stderr)
        
        metadata_json = extracted_data[4:4+metadata_length]
        metadata = json.loads(metadata_json.decode('utf-8'))
        print(f'Metadata: {metadata}', file=sys.stderr)
        
        # Get IV and encrypted
        iv_start = 4 + metadata_length
        iv = extracted_data[iv_start:iv_start+16]
        encrypted_data = extracted_data[iv_start+16:]
        
        print(f'Encrypted data size: {len(encrypted_data)} bytes', file=sys.stderr)
        
        # Decrypt
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            print(f'Decrypted data size: {len(decrypted_data)} bytes', file=sys.stderr)
        except:
            return {'success': False, 'error': 'Invalid key'}
        
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
        output_path = os.path.join(output_dir, f"extracted_{os.path.basename(stego_path)}")
        img.save(output_path)
        
        print(f'✅ Extracted: {output_path}', file=sys.stderr)
        
        return {
            'success': True,
            'decrypted_path': output_path,
            'message': 'Extraction successful'
        }
        
    except Exception as e:
        print(f'❌ Decryption failed: {str(e)}', file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'success': False, 'error': 'Invalid arguments'}))
        return
    
    command = sys.argv[1]
    
    try:
        if command == 'encrypt' and len(sys.argv) >= 5:
            result = encrypt_with_steganography(
                sys.argv[2], sys.argv[3], sys.argv[4],
                sys.argv[5] if len(sys.argv) > 5 else 'logistic'
            )
        elif command == 'decrypt' and len(sys.argv) >= 4:
            result = decrypt_from_steganography(sys.argv[2], sys.argv[3])
        else:
            result = {'success': False, 'error': 'Invalid command'}
        
        print(json.dumps(result))
        
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))

if __name__ == '__main__':
    main()
