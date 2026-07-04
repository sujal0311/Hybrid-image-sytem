# python/encryption.py
import sys
import json
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import io
import time

# ── Safe Logging ──────────────────────────────────────────────────────────────
def log(message):
    """Log to stderr to prevent corrupting JSON stdout"""
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
    vals = np.zeros(size, dtype=np.float64)
    for i in range(size):
        x = 3.99 * x * (1 - x)
        vals[i] = x
    return np.argsort(vals)

def _tent_permutation(size, seed=0.5):
    x = seed
    vals = np.zeros(size, dtype=np.float64)
    for i in range(size):
        x = 2 * x if x < 0.5 else 2 * (1 - x)
        vals[i] = x
    return np.argsort(vals)

def _henon_permutation(size, seed=0.5):
    x, y = seed, seed
    vals = np.zeros(size, dtype=np.float64)
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

# ── Normalize image mode for safe round-trip ─────────────────────────────────
def _normalize_image(img):
    """
    Convert image to a safe mode for encrypt/decrypt round-trip.
    - P (palette), LA, PA  → RGBA
    - L (grayscale)        → kept as L
    - RGB / RGBA           → kept as-is
    Any mode not natively supported by PIL.fromarray is converted to RGBA.
    """
    safe_modes = {'L', 'RGB', 'RGBA'}
    if img.mode in safe_modes:
        return img
    # Palette / transparency modes → RGBA
    return img.convert('RGBA')

# ── Encrypt ───────────────────────────────────────────────────────────────────
def encrypt_image(image_path, key, chaotic_map='logistic'):
    """Encrypt image to .bin file with metrics"""
    try:
        start_time = time.time()
        log(f'Encrypting image: {image_path} with map: {chaotic_map}')

        img = Image.open(image_path)

        # ✅ FIX 1: Normalize to a safe PIL mode before touching numpy
        img = _normalize_image(img)

        # ✅ FIX 2: Explicit contiguous uint8 copy — never a view, never read-only
        img_array = np.ascontiguousarray(np.array(img), dtype=np.uint8)

        original_entropy = calculate_entropy(img_array)

        # Store metadata — use the normalised mode & real array shape/dtype
        metadata = {
            'mode':        img.mode,
            'shape':       list(img_array.shape),
            'dtype':       str(img_array.dtype),   # always 'uint8' now
            'chaotic_map': chaotic_map
        }

        # Layer 1: Chaotic Scrambling (Keyed)
        log('Applying chaotic scramble...')
        flat_img = img_array.flatten()
        seed     = _derive_chaotic_seed(key)
        perm     = _get_permutation(len(flat_img), chaotic_map, seed)

        # ✅ FIX 3: .copy() after fancy-indexing → writable, contiguous array
        scrambled_flat = flat_img[perm].copy()
        img_bytes      = scrambled_flat.tobytes()

        metadata_json   = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)

        # Layer 2: AES-256-CBC encryption
        log('Applying AES-256-CBC encryption...')
        key_bytes    = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher       = AES.new(key_bytes, AES.MODE_CBC)
        iv           = cipher.iv
        padded_data  = pad(img_bytes, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        encrypted_entropy = calculate_entropy(
            np.frombuffer(encrypted_data, dtype=np.uint8)
        )

        # Save encrypted file
        base_name   = os.path.splitext(image_path)[0]
        output_path = f"{base_name}_encrypted.bin"

        with open(output_path, 'wb') as f:
            # Format: metadata_length(4) + metadata_json + IV(16) + encrypted_data
            f.write(metadata_length.to_bytes(4, byteorder='big'))
            f.write(metadata_json)
            f.write(iv)
            f.write(encrypted_data)

        log(f'Encryption successful: {output_path}')
        encryption_time_ms = (time.time() - start_time) * 1000
        log(f'Encryption took {encryption_time_ms:.2f} ms')
        
        metrics_output = {
            'encryptionTime': round(encryption_time_ms, 2),
            'entropy': {
                'original':  round(original_entropy,  4),
                'encrypted': round(encrypted_entropy, 4)
            },
            'size': os.path.getsize(output_path)
        }
        log(f'Metrics: {json.dumps(metrics_output)}')
        
        return {
            'success': True,
            'encrypted_path': output_path,
            'message': 'Encryption successful',
            'metrics': metrics_output
        }

    except Exception as e:
        log(f'Encryption error: {str(e)}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}


# ── Decrypt ───────────────────────────────────────────────────────────────────
def decrypt_image(encrypted_path, key):
    """Decrypt .bin file back to image"""
    try:
        start_time = time.time()
        log(f'Decrypting file: {encrypted_path}')

        with open(encrypted_path, 'rb') as f:
            metadata_length = int.from_bytes(f.read(4), byteorder='big')
            metadata_json   = f.read(metadata_length)
            metadata        = json.loads(metadata_json.decode('utf-8'))
            iv              = f.read(16)
            encrypted_data  = f.read()

        chaotic_map = metadata.get('chaotic_map', 'logistic')
        shape       = tuple(metadata['shape'])
        mode        = metadata['mode']
        # ✅ FIX 4: always treat stored dtype as uint8 (it was always uint8 on encrypt)
        dtype       = np.dtype(metadata.get('dtype', 'uint8'))

        # Layer 2 Reverse: AES Decrypt
        log('Reversing AES decryption...')
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        cipher    = AES.new(key_bytes, AES.MODE_CBC, iv=iv)

        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except ValueError:
            return {'success': False, 'error': 'Invalid key or corrupted file'}

        # ✅ FIX 5: .copy() on frombuffer result → writable numpy array
        flat_scrambled = np.frombuffer(decrypted_data, dtype=dtype).copy()

        # Sanity-check: total elements must match shape
        expected_elements = 1
        for s in shape:
            expected_elements *= s

        if len(flat_scrambled) != expected_elements:
            return {
                'success': False,
                'error': (
                    f'Data size mismatch after decryption: '
                    f'got {len(flat_scrambled)} elements, expected {expected_elements}. '
                    f'Wrong key or corrupted file.'
                )
            }

        # Layer 1 Reverse: Unscramble (Keyed)
        log(f'Reversing chaotic scramble ({chaotic_map})...')
        seed         = _derive_chaotic_seed(key)
        perm         = _get_permutation(len(flat_scrambled), chaotic_map, seed)
        original_flat = np.zeros_like(flat_scrambled)
        original_flat[perm] = flat_scrambled

        # ✅ FIX 6: np.ascontiguousarray → guaranteed writable, contiguous uint8 block
        img_array = np.ascontiguousarray(original_flat.reshape(shape), dtype=np.uint8)

        # ✅ FIX 7: validate mode vs channels before calling PIL
        channels = img_array.shape[2] if img_array.ndim == 3 else 1
        mode_channels = {'L': 1, 'RGB': 3, 'RGBA': 4}
        if mode_channels.get(mode, -1) != channels:
            # Fall back to a safe mode derived from channel count
            mode = {1: 'L', 3: 'RGB', 4: 'RGBA'}.get(channels, 'RGB')
            log(f'Mode mismatch corrected → using {mode}')

        # Build PIL image from the clean array
        if img_array.ndim == 2:
            img = Image.fromarray(img_array, mode='L')
        else:
            img = Image.fromarray(img_array, mode=mode)

        # ✅ FIX 8: save via BytesIO first to catch silent PIL encoding failures
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        # Verify the PNG is readable before writing to disk
        Image.open(buf).verify()
        buf.seek(0)

        base_name   = os.path.splitext(encrypted_path)[0]
        output_path = f"{base_name}_decrypted.png"
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        with open(output_path, 'wb') as out_f:
            out_f.write(buf.read())

        log(f'Decryption successful: {output_path}')
        decryption_time_ms = (time.time() - start_time) * 1000
        return {
            'success': True,
            'decrypted_path': output_path,
            'message': 'Decryption successful',
            'metrics': {
                'encryptionTime': round(decryption_time_ms, 2)
            }
        }

    except Exception as e:
        log(f'Decryption error: {str(e)}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    try:
        if len(sys.argv) < 2:
            print(json.dumps({'success': False, 'error': 'Invalid arguments'}))
            return

        command = sys.argv[1]

        if command == 'encrypt' and len(sys.argv) >= 4:
            image_path  = sys.argv[2]
            key         = sys.argv[3]
            chaotic_map = sys.argv[4] if len(sys.argv) > 4 else 'logistic'
            result      = encrypt_image(image_path, key, chaotic_map)

        elif command == 'decrypt' and len(sys.argv) >= 4:
            encrypted_path = sys.argv[2]
            key            = sys.argv[3]
            result         = decrypt_image(encrypted_path, key)

        else:
            result = {'success': False, 'error': 'Invalid command'}

        # CRITICAL: Print ONLY JSON to stdout
        print(json.dumps(result), flush=True)

    except Exception as e:
        log(f"Fatal error in main: {str(e)}")
        print(json.dumps({'success': False, 'error': str(e)}), flush=True)
        sys.exit(1)

if __name__ == '__main__':
    main()