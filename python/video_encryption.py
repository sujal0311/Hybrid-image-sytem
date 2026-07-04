"""
python/video_encryption.py
Fully Fixed & Optimized
"""

import sys
import json
import numpy as np
import os
import cv2
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Logging to stderr only ────────────────────────────────────────────────────
def log(msg):
    print(msg, file=sys.stderr, flush=True)

# ── Chaotic scrambling (key-derived seed) ─────────────────────────────────────
def _derive_chaotic_seed(key_str: str) -> float:
    """Derive a stable chaotic initial condition from the encryption key."""
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

def get_permutation(size, chaotic_map='logistic', seed=0.5):
    if chaotic_map == 'tent':
        return _tent_permutation(size, seed)
    elif chaotic_map == 'henon':
        return _henon_permutation(size, seed)
    else:
        return _logistic_permutation(size, seed)

def scramble_frames(frames, chaotic_map, seed):
    """Scramble frame order using keyed chaotic permutation."""
    n = len(frames)
    perm = get_permutation(n, chaotic_map, seed)
    return [frames[i] for i in perm], perm.tolist()

def unscramble_frames(frames, perm):
    """Restore original frame order."""
    n = len(frames)
    result = [None] * n
    for new_idx, orig_idx in enumerate(perm):
        result[orig_idx] = frames[new_idx]
    return result

# ── AES helpers ───────────────────────────────────────────────────────────────
def make_key(key_str):
    return key_str.encode('utf-8')[:32].ljust(32, b'\0')

def aes_encrypt(data: bytes, key_str: str):
    key = make_key(key_str)
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct          # prepend IV

def aes_decrypt(data: bytes, key_str: str):
    key = make_key(key_str)
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ── Entropy helper ────────────────────────────────────────────────────────────
def entropy(data: bytes) -> float:
    if not data: return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    hist = hist[hist > 0].astype(float)
    hist /= hist.sum()
    return float(-np.sum(hist * np.log2(hist)))

# ─────────────────────────────────────────────────────────────────────────────
# ENCRYPT
# ─────────────────────────────────────────────────────────────────────────────
def encrypt_video(video_path: str, key: str, chaotic_map: str = 'logistic'):
    try:
        start_time = time.time()
        log(f'Opening video: {video_path}')
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return {'success': False, 'error': 'Cannot open video file'}

        fps      = cap.get(cv2.CAP_PROP_FPS) or 25.0
        width    = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        frames = []
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
        cap.release()

        if not frames:
            return {'success': False, 'error': 'No frames found in video'}

        total_frames = len(frames)
        log(f'Read {total_frames} frames  {width}x{height}  fps={fps}')

        # ── Entropy of original (sample first frame) ──
        orig_entropy = entropy(frames[0].tobytes())

        # ── Chaotic frame scrambling (Keyed) ──
        seed = _derive_chaotic_seed(key)
        scrambled_frames, _ = scramble_frames(frames, chaotic_map, seed)
        log(f'Frames scrambled using {chaotic_map} map')

        # ── Flatten all frames → bytes → AES encrypt ──
        raw_bytes = b''.join(f.tobytes() for f in scrambled_frames)
        log(f'Raw video bytes: {len(raw_bytes)}')

        encrypted_bytes = aes_encrypt(raw_bytes, key)
        enc_entropy = entropy(encrypted_bytes[:min(len(encrypted_bytes), 65536)])
        log(f'Encrypted bytes: {len(encrypted_bytes)}')

        # ── Build output file ──
        # NO PERMUTATION ARRAY STORED
        metadata = {
            'fps':         fps,
            'width':       width,
            'height':      height,
            'frames':      total_frames,
            'chaotic_map': chaotic_map,
            'dtype':       str(frames[0].dtype),
            'channels':    frames[0].shape[2] if len(frames[0].shape) == 3 else 1
        }
        meta_json  = json.dumps(metadata).encode('utf-8')
        meta_len   = len(meta_json).to_bytes(4, 'big')

        base   = os.path.splitext(video_path)[0]
        out_path = f'{base}_encrypted.vbin'
        with open(out_path, 'wb') as f:
            f.write(meta_len)
            f.write(meta_json)
            f.write(encrypted_bytes)

        log(f'Saved: {out_path}')
        encryption_time_ms = (time.time() - start_time) * 1000
        log(f'Encryption took {encryption_time_ms:.2f} ms')
        
        metrics_output = {
            'encryptionTime': round(encryption_time_ms, 2),
            'entropy': {
                'original':  round(orig_entropy, 4),
                'encrypted': round(enc_entropy,  4)
            },
            'frames':      total_frames,
            'fps':         fps,
            'resolution':  f'{width}x{height}',
            'size':        os.path.getsize(out_path)
        }
        log(f'Metrics: {json.dumps(metrics_output)}')
        
        return {
            'success': True,
            'encrypted_path': out_path,
            'message': 'Video encrypted successfully',
            'metrics': metrics_output
        }

    except Exception as e:
        log(f'encrypt_video error: {e}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# DECRYPT
# ─────────────────────────────────────────────────────────────────────────────
def decrypt_video(encrypted_path: str, key: str):
    try:
        log(f'Reading encrypted video: {encrypted_path}')
        with open(encrypted_path, 'rb') as f:
            meta_len       = int.from_bytes(f.read(4), 'big')
            meta_json      = f.read(meta_len)
            encrypted_bytes = f.read()

        metadata  = json.loads(meta_json.decode('utf-8'))
        fps       = metadata['fps']
        width     = metadata['width']
        height    = metadata['height']
        total_frames = metadata['frames']
        dtype     = np.dtype(metadata['dtype'])
        channels  = metadata['channels']
        chaotic_map = metadata.get('chaotic_map', 'logistic')

        log(f'Metadata: {total_frames} frames  {width}x{height}  fps={fps}')

        # ── AES decrypt ──
        try:
            raw_bytes = aes_decrypt(encrypted_bytes, key)
        except Exception:
            return {'success': False, 'error': 'Invalid key or corrupted file'}

        # ── Reconstruct frames ──
        frame_size = height * width * channels * dtype.itemsize
        if len(raw_bytes) < frame_size * total_frames:
            return {'success': False, 'error': 'Decrypted data size mismatch'}

        scrambled_frames = []
        for i in range(total_frames):
            chunk = raw_bytes[i*frame_size:(i+1)*frame_size]
            frame = np.frombuffer(chunk, dtype=dtype).reshape(height, width, channels)
            scrambled_frames.append(frame.copy())

        # ── Reverse frame scrambling (Keyed) ──
        seed = _derive_chaotic_seed(key)
        perm = get_permutation(total_frames, chaotic_map, seed)
        frames = unscramble_frames(scrambled_frames, perm.tolist())
        log('Frames unscrambled')

        # ── Write output video ──
        base     = os.path.splitext(encrypted_path)[0]
        out_path = f'{base}_decrypted.mp4'
        fourcc   = cv2.VideoWriter_fourcc(*'mp4v')
        out_dir  = os.path.dirname(out_path)
        os.makedirs(out_dir, exist_ok=True)

        writer = cv2.VideoWriter(out_path, fourcc, fps, (width, height))
        for frame in frames:
            writer.write(frame.astype(np.uint8))
        writer.release()

        log(f'Saved decrypted video: {out_path}')
        return {
            'success': True,
            'decrypted_path': out_path,
            'message': 'Video decrypted successfully'
        }

    except Exception as e:
        log(f'decrypt_video error: {e}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 4:
        print(json.dumps({'success': False, 'error': 'Usage: video_encryption.py <encrypt|decrypt> <path> <key> [chaotic_map]'}))
        return

    cmd   = sys.argv[1]
    path_ = sys.argv[2]
    key   = sys.argv[3]
    cmap  = sys.argv[4] if len(sys.argv) > 4 else 'logistic'

    if cmd == 'encrypt':
        result = encrypt_video(path_, key, cmap)
    elif cmd == 'decrypt':
        result = decrypt_video(path_, key)
    else:
        result = {'success': False, 'error': f'Unknown command: {cmd}'}

    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()