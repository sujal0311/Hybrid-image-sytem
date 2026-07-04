# python/steganography.py
import sys
import json
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import io
import hashlib
import math

# ── Logging to stderr only ────────────────────────────────────────────────────
def log(message):
    """Safe logging to stderr to prevent corrupting JSON stdout"""
    print(message, file=sys.stderr, flush=True)

# ── Chaotic Scrambling (Key-Derived Seed) ─────────────────────────────────────
def _derive_chaotic_seed(key_str: str) -> float:
    """Derive a stable chaotic initial condition from the key."""
    if not key_str:
        return 0.5000
    h = hashlib.sha256(key_str.encode("utf-8")).digest()
    val = int.from_bytes(h[:8], "big")
    seed = val / (2**64 - 1)
    if seed < 0.0001: seed = 0.0001
    elif seed > 0.9999: seed = 0.9999
    return seed

def _logistic_permutation(size, seed=0.5):
    x = seed
    vals = np.zeros(size)
    for i in range(size):
        x = 3.99 * x * (1 - x)
        vals[i] = x
    return np.argsort(vals)

def _tent_permutation(size, seed=0.5):
    x = seed
    vals = np.zeros(size)
    for i in range(size):
        x = 2 * x if x < 0.5 else 2 * (1 - x)
        vals[i] = x
    return np.argsort(vals)

def _henon_permutation(size, seed=0.5):
    x, y = seed, seed
    vals = np.zeros(size)
    for i in range(size):
        x, y = 1 - 1.4 * x * x + y, 0.3 * x
        vals[i] = abs(x)
    return np.argsort(vals)

def _get_permutation(size, chaotic_map='logistic', seed=0.5):
    if chaotic_map == 'tent':
        return _tent_permutation(size, seed)
    elif chaotic_map == 'henon':
        return _henon_permutation(size, seed)
    else:
        return _logistic_permutation(size, seed)

# ── Metrics ───────────────────────────────────────────────────────────────────
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

def _psnr(orig, stego):
    mse = np.mean((orig.astype(float) - stego.astype(float)) ** 2)
    if mse == 0: return float('inf')
    return 20 * math.log10(255.0 / math.sqrt(mse))

# ── Fast LSB Embedding/Extraction ─────────────────────────────────────────────
def embed_lsb_fast(cover_image, secret_data):
    """FAST LSB embedding using NumPy vectorization"""
    try:
        if cover_image.mode != 'RGB':
            cover_image = cover_image.convert('RGB')
        
        cover_array = np.array(cover_image, dtype=np.uint8)
        log(f'Cover array shape: {cover_array.shape}')
        
        data_bits = np.unpackbits(np.frombuffer(secret_data, dtype=np.uint8))
        data_length = len(data_bits)
        
        # Create length header (32 bits)
        length_bits = np.array([int(b) for b in format(data_length, '032b')], dtype=np.uint8)
        all_bits = np.concatenate([length_bits, data_bits])
        
        log(f'Total bits to embed: {len(all_bits)}')
        
        flat_cover = cover_array.flatten()
        capacity = len(flat_cover)
        
        if len(all_bits) > capacity:
            raise ValueError(f'Cover too small: need {len(all_bits)} bits, have {capacity}')
        
        log(f'Embedding {len(all_bits)} bits...')
        flat_cover[:len(all_bits)] = (flat_cover[:len(all_bits)] & 0xFE) | all_bits
        
        stego_array = flat_cover.reshape(cover_array.shape)
        stego_image = Image.fromarray(stego_array, mode='RGB')
        
        return stego_image, cover_array, stego_array
        
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
        
        length_bits = stego_array[:32] & 1
        data_length = int(''.join(str(b) for b in length_bits), 2)
        
        log(f'Data length: {data_length} bits')
        
        if data_length <= 0 or data_length > len(stego_array) - 32:
            raise ValueError(f'Invalid data length: {data_length}')
        
        data_bits = stego_array[32:32+data_length] & 1
        
        remainder = len(data_bits) % 8
        if remainder != 0:
            data_bits = np.concatenate([data_bits, np.zeros(8 - remainder, dtype=np.uint8)])
        
        secret_bytes = np.packbits(data_bits).tobytes()
        log(f'Converted to {len(secret_bytes)} bytes')
        
        return secret_bytes
        
    except Exception as e:
        log(f'LSB extraction error: {str(e)}')
        raise

# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC — HIDE
# ─────────────────────────────────────────────────────────────────────────────
def encrypt_with_steganography(secret_path, cover_path, key, chaotic_map='logistic'):
    """Triple-layer encryption with FAST embedding"""
    try:
        log('Starting steganography encryption...')
        
        # Load secret
        secret_img = Image.open(secret_path)
        if secret_img.mode not in ['RGB', 'L']:
            secret_img = secret_img.convert('RGB')
        
        secret_array = np.array(secret_img)
        original_entropy = calculate_entropy(secret_array)
        
        metadata = {
            'mode': secret_img.mode,
            'shape': list(secret_array.shape),
            'dtype': str(secret_array.dtype),
            'chaotic_map': chaotic_map
        }
        
        # Layer 1: Chaotic Scrambling (Keyed)
        log(f'Scrambling using {chaotic_map} map...')
        flat_secret = secret_array.flatten()
        seed = _derive_chaotic_seed(key)
        perm = _get_permutation(len(flat_secret), chaotic_map, seed)
        scrambled_secret = flat_secret[perm]
        
        secret_bytes = scrambled_secret.tobytes()
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Layer 2: AES
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        padded_data = pad(secret_bytes, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        encrypted_entropy = calculate_entropy(np.frombuffer(encrypted_data, dtype=np.uint8))
        
        full_data = (
            metadata_length.to_bytes(4, byteorder='big') +
            metadata_json +
            cipher.iv +
            encrypted_data
        )
        
        # Layer 3: LSB
        cover_img = Image.open(cover_path)
        stego_img, orig_arr, stego_arr = embed_lsb_fast(cover_img, full_data)
        
        # Metrics
        psnr_val = _psnr(orig_arr, stego_arr)
        
        # Save
        output_dir = os.path.dirname(os.path.abspath(cover_path))
        os.makedirs(output_dir, exist_ok=True)
        
        base_name = os.path.splitext(os.path.basename(cover_path))[0]
        stego_path = os.path.join(output_dir, f"{base_name}_stego.png")
        stego_img.save(stego_path, 'PNG')
        
        return {
            'success': True,
            'stego_path': stego_path,
            'message': 'Triple-layer encryption successful',
            'metrics': {
                'chaotic_map': chaotic_map,
                'entropy': {
                    'original': round(original_entropy, 4),
                    'encrypted': round(encrypted_entropy, 4)
                },
                'psnr': f'{psnr_val:.2f} dB' if psnr_val != float('inf') else 'inf',
                'size': os.path.getsize(stego_path)
            }
        }
        
    except Exception as e:
        log(f'❌ Encryption failed: {str(e)}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC — REVEAL
# ─────────────────────────────────────────────────────────────────────────────
def decrypt_from_steganography(stego_path, key):
    """Triple-layer decryption with FAST extraction"""
    try:
        log('Starting steganography decryption...')
        
        stego_img = Image.open(stego_path)
        
        # Layer 3 Reverse: LSB
        extracted_data = extract_lsb_fast(stego_img)
        
        metadata_length = int.from_bytes(extracted_data[:4], byteorder='big')
        metadata_json = extracted_data[4:4+metadata_length]
        
        try:
            metadata = json.loads(metadata_json.decode('utf-8'))
        except Exception:
            return {'success': False, 'error': 'Corrupted metadata or no hidden data found.'}
            
        iv_start = 4 + metadata_length
        iv = extracted_data[iv_start:iv_start+16]
        encrypted_data = extracted_data[iv_start+16:]
        
        chaotic_map = metadata.get('chaotic_map', 'logistic')
        
        # Layer 2 Reverse: AES
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except Exception:
            return {'success': False, 'error': 'Invalid key or corrupted data'}
        
        # Layer 1 Reverse: Unscramble (Keyed)
        shape = tuple(metadata['shape'])
        dtype = np.dtype(metadata['dtype'])
        flat_scrambled = np.frombuffer(decrypted_data, dtype=dtype)
        
        seed = _derive_chaotic_seed(key)
        perm = _get_permutation(len(flat_scrambled), chaotic_map, seed)
        
        original_flat = np.zeros_like(flat_scrambled)
        original_flat[perm] = flat_scrambled
        img_array = original_flat.reshape(shape)
        
        # Save
        img = Image.fromarray(img_array.astype(np.uint8), mode=metadata['mode'])
        output_dir = os.path.dirname(stego_path) or '/tmp/uploads/decrypted'
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"extracted_{os.path.basename(stego_path)}")
        img.save(output_path)
        
        return {
            'success': True,
            'decrypted_path': output_path,
            'message': 'Extraction successful',
            'metrics': {
                'chaotic_map': chaotic_map,
            }
        }
        
    except Exception as e:
        log(f'❌ Decryption failed: {str(e)}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
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
        
        # CRITICAL: Print ONLY JSON to stdout
        print(json.dumps(result), flush=True)
        
    except Exception as e:
        log(f'Fatal error in main: {str(e)}')
        print(json.dumps({'success': False, 'error': str(e)}), flush=True)
        sys.exit(1)

if __name__ == '__main__':
    main()