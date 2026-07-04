"""
python/video_steganography.py
Triple-Layer Video Steganography (PROPER IMPLEMENTATION):
  Layer 1 → Chaotic byte scrambling (key-derived seed, no perm stored)
  Layer 2 → AES-256-CBC encryption
  Layer 3 → LSB embedding into Blue-channel pixels of a chosen video frame

Output video is AVI (lossless HFYU or uncompressed) to preserve LSBs exactly.
"""

import sys
import json
import os
import struct
import math
import time
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Logging (stderr only to protect JSON stdout) ──────────────────────────────
def log(msg):
    print(msg, file=sys.stderr, flush=True)

# ═════════════════════════════════════════════════════════════════════════════
# LAYER 1 — Chaotic Scrambling (Key-Derived Seed)
# ═════════════════════════════════════════════════════════════════════════════

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

def scramble_bytes(data: bytes, chaotic_map='logistic', seed=0.5) -> bytes:
    if not data: return b""
    arr  = np.frombuffer(data, dtype=np.uint8).copy()
    perm = _get_permutation(len(arr), chaotic_map, seed)
    return arr[perm].tobytes()

def unscramble_bytes(data: bytes, perm: list) -> bytes:
    if not data: return b""
    arr    = np.frombuffer(data, dtype=np.uint8).copy()
    result = np.zeros_like(arr)
    result[perm] = arr
    return result.tobytes()

# ═════════════════════════════════════════════════════════════════════════════
# LAYER 2 — AES-256-CBC
# ═════════════════════════════════════════════════════════════════════════════

def _make_key(key_str: str) -> bytes:
    return key_str.encode('utf-8')[:32].ljust(32, b'\0')

def aes_encrypt(data: bytes, key_str: str) -> bytes:
    key    = _make_key(key_str)
    cipher = AES.new(key, AES.MODE_CBC)
    ct     = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct

def aes_decrypt(data: bytes, key_str: str) -> bytes:
    key    = _make_key(key_str)
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ═════════════════════════════════════════════════════════════════════════════
# LAYER 3 — LSB in video frame (Blue channel)
# ═════════════════════════════════════════════════════════════════════════════

def _bits_from_bytes(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _bytes_from_bits(bits):
    result = bytearray()
    buf, count = 0, 0
    for bit in bits:
        buf = (buf << 1) | int(bit)
        count += 1
        if count == 8:
            result.append(buf)
            buf = count = 0
    return bytes(result)

def _embed_in_frame(frame: np.ndarray, payload: bytes) -> np.ndarray:
    h, w   = frame.shape[:2]
    capacity = h * w

    bits_needed = 64 + 8 * len(payload)
    if capacity < bits_needed:
        raise ValueError(
            f'Frame too small. Need {bits_needed} pixels, frame has {capacity}. '
            f'Use higher-resolution video or a smaller secret file.'
        )

    header   = struct.pack('>Q', len(payload))
    all_bits = list(_bits_from_bytes(header)) + list(_bits_from_bytes(payload))

    stego     = frame.copy()
    blue_flat = stego[:, :, 0].flatten().astype(np.int32)

    for idx, bit in enumerate(all_bits):
        blue_flat[idx] = (blue_flat[idx] & 0xFE) | int(bit)

    stego[:, :, 0] = blue_flat.reshape(h, w).astype(np.uint8)
    return stego

def _extract_from_frame(frame: np.ndarray) -> bytes:
    blue_flat = frame[:, :, 0].flatten()
    capacity  = len(blue_flat)

    if capacity < 64:
        raise ValueError('Frame too small to contain a valid header.')

    header_bits = [int(blue_flat[i]) & 1 for i in range(64)]
    payload_len = struct.unpack('>Q', _bytes_from_bits(header_bits))[0]

    if payload_len == 0 or capacity < 64 + 8 * payload_len:
        raise ValueError(
            f'Invalid payload length ({payload_len}) in frame. '
            'Frame may not contain hidden data or codec destroyed LSBs.'
        )

    data_bits = [int(blue_flat[64 + i]) & 1 for i in range(8 * payload_len)]
    return _bytes_from_bits(data_bits)

# ═════════════════════════════════════════════════════════════════════════════
# Metrics
# ═════════════════════════════════════════════════════════════════════════════

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    hist = hist[hist > 0].astype(float)
    hist /= hist.sum()
    return float(-np.sum(hist * np.log2(hist)))

def _frame_psnr(orig: np.ndarray, stego: np.ndarray) -> float:
    mse = np.mean((orig.astype(float) - stego.astype(float)) ** 2)
    if mse == 0:
        return float('inf')
    return 20 * math.log10(255.0 / math.sqrt(mse))

def _detect_type(header: bytes) -> str:
    sigs = {
        b'\xff\xd8\xff': 'JPEG Image', b'\x89PNG': 'PNG Image', b'GIF8': 'GIF Image',
        b'%PDF': 'PDF Document', b'RIFF': 'WAV Audio', b'ID3': 'MP3 Audio',
        b'\x1f\x8b': 'GZIP', b'PK\x03\x04': 'ZIP Archive',
    }
    for sig, name in sigs.items():
        if header[:len(sig)] == sig: return name
    try:
        header.decode('utf-8')
        return 'Text File'
    except:
        return 'Binary Data'

# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC — HIDE
# ═════════════════════════════════════════════════════════════════════════════

def hide_in_video(secret_path, cover_path, output_path, key, frame_index=0, chaotic_map='logistic'):
    try:
        import cv2
        t0 = time.time()

        log(f'[HIDE] Reading secret: {secret_path}')
        with open(secret_path, 'rb') as f:
            secret_raw = f.read()

        orig_entropy = _entropy(secret_raw)
        seed = _derive_chaotic_seed(key)

        log(f'[HIDE] Layer 1: Chaotic scrambling ({chaotic_map}) with key-derived seed...')
        scrambled = scramble_bytes(secret_raw, chaotic_map, seed)

        log('[HIDE] Layer 2: AES-256-CBC encryption...')
        encrypted   = aes_encrypt(scrambled, key)
        enc_entropy = _entropy(encrypted)

        metadata = {
            'chaotic_map': chaotic_map,
            'secret_size': len(secret_raw),
            'orig_name':   os.path.basename(secret_path)
        }
        meta_json = json.dumps(metadata).encode('utf-8')
        payload   = struct.pack('>I', len(meta_json)) + meta_json + encrypted
        
        log(f'[HIDE] Opening cover video: {cover_path}')
        cap = cv2.VideoCapture(cover_path)
        if not cap.isOpened():
            return {'success': False, 'error': f'Cannot open video: {cover_path}'}

        fps    = cap.get(cv2.CAP_PROP_FPS) or 25.0
        width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        total  = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        if frame_index >= total:
            cap.release()
            return {'success': False, 'error': f'frame_index={frame_index} out of range (video has {total} frames).'}

        frames = []
        while True:
            ret, frm = cap.read()
            if not ret: break
            frames.append(frm)
        cap.release()

        log(f'[HIDE] Layer 3: LSB embedding into frame {frame_index}...')
        original_frame = frames[frame_index].copy()
        try:
            frames[frame_index] = _embed_in_frame(frames[frame_index], payload)
        except ValueError as ve:
            return {'success': False, 'error': str(ve)}

        stego_frame = frames[frame_index]

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        if not output_path.lower().endswith('.avi'):
            return {
                'success': False,
                'error': 'Stego video must be saved as lossless AVI (.avi). '
                         'Use .avi output to preserve hidden bits.'
            }

        fourcc_candidates = [
            cv2.VideoWriter_fourcc(*'HFYU'),
            cv2.VideoWriter_fourcc(*'FFV1'),
            0
        ]

        out = None
        for fourcc in fourcc_candidates:
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            if out.isOpened():
                break

        if out is None or not out.isOpened():
            return {
                'success': False,
                'error': 'Cannot create lossless output video. '
                         'Ensure OpenCV supports HFYU/FFV1 or use uncompressed AVI.'
            }

        for frm in frames:
            out.write(frm)
        out.release()

        elapsed  = round(time.time() - t0, 2)
        psnr_val = _frame_psnr(original_frame, stego_frame)

        return {
            'success':    True,
            'stego_path': output_path,
            'message':    'Triple-layer video steganography successful',
            'metrics': {
                'layers':          ['Chaotic Scrambling', 'AES-256-CBC', 'LSB Steganography'],
                'chaotic_map':     chaotic_map,
                'entropy': {
                    'original':  round(orig_entropy, 4),
                    'encrypted': round(enc_entropy,  4)
                },
                'psnr':            f'{psnr_val:.2f} dB' if psnr_val != float('inf') else 'inf',
                'frame_used':      frame_index,
                'total_frames':    total,
                'resolution':      f'{width}x{height}',
                'fps':             fps,
                'processing_time': elapsed
            }
        }

    except ImportError:
        return {'success': False, 'error': 'OpenCV not installed. Run: pip install opencv-python'}
    except Exception as e:
        log(f'hide_in_video error: {e}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC — REVEAL
# ═════════════════════════════════════════════════════════════════════════════

def reveal_from_video(stego_path, output_path, key, frame_index=0):
    try:
        import cv2
        t0 = time.time()

        log(f'[REVEAL] Opening stego video: {stego_path}')
        cap = cv2.VideoCapture(stego_path)
        if not cap.isOpened():
            return {'success': False, 'error': f'Cannot open video: {stego_path}'}

        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if frame_index >= total:
            cap.release()
            return {'success': False, 'error': f'frame_index out of range.'}

        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
        ret, frame = cap.read()
        cap.release()

        if not ret: return {'success': False, 'error': f'Could not read frame {frame_index}.'}

        log(f'[REVEAL] Layer 3 reverse: LSB extraction from frame {frame_index}...')
        try:
            payload = _extract_from_frame(frame)
        except ValueError as ve:
            return {'success': False, 'error': str(ve)}

        if len(payload) < 4:
            return {'success': False, 'error': 'Payload too small — possibly no hidden data.'}
        
        meta_len = struct.unpack('>I', payload[:4])[0]
        if 4 + meta_len > len(payload):
            return {'success': False, 'error': 'Metadata length mismatch — file may be corrupted.'}
        
        try:
            metadata = json.loads(payload[4:4 + meta_len].decode('utf-8'))
        except Exception:
            return {'success': False, 'error': 'Cannot parse metadata.'}

        chaotic_map = metadata.get('chaotic_map', 'logistic')
        encrypted   = payload[4 + meta_len:]

        seed = _derive_chaotic_seed(key)

        log('[REVEAL] Layer 2 reverse: AES-256-CBC decryption...')
        try:
            scrambled = aes_decrypt(encrypted, key)
        except Exception:
            return {'success': False, 'error': 'AES decryption failed — wrong key or corrupted data.'}

        log(f'[REVEAL] Layer 1 reverse: Chaotic unscrambling ({chaotic_map})...')
        perm = _get_permutation(len(scrambled), chaotic_map, seed)
        secret_raw = unscramble_bytes(scrambled, perm.tolist())

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(secret_raw)

        elapsed   = round(time.time() - t0, 3)
        file_type = _detect_type(secret_raw[:16])

        return {
            'success':        True,
            'extracted_path': output_path,
            'message':        'Triple-layer video steganography reveal successful',
            'metrics': {
                'layers':          ['LSB Extraction', 'AES-256-CBC Decryption', 'Chaotic Unscrambling'],
                'chaotic_map':     chaotic_map,
                'extracted_size':  f'{len(secret_raw)} bytes',
                'file_type':       file_type,
                'frame_used':      frame_index,
                'total_frames':    total,
                'processing_time': elapsed
            }
        }

    except ImportError:
        return {'success': False, 'error': 'OpenCV not installed.'}
    except Exception as e:
        log(f'reveal_from_video error: {e}')
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    try:
        if len(sys.argv) < 2:
            print(json.dumps({'success': False, 'error': 'Provide hide or reveal command'}))
            return

        cmd = sys.argv[1].lower()

        if cmd == 'hide':
            if len(sys.argv) < 6:
                print(json.dumps({'success': False, 'error': 'hide requires: secret cover output key [frame_index] [chaotic_map]'}))
                return
            fi   = int(sys.argv[6])   if len(sys.argv) > 6 else 0
            cmap = sys.argv[7]        if len(sys.argv) > 7 else 'logistic'
            result = hide_in_video(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], fi, cmap)

        elif cmd == 'reveal':
            if len(sys.argv) < 5:
                print(json.dumps({'success': False, 'error': 'reveal requires: stego output key [frame_index]'}))
                return
            fi     = int(sys.argv[5]) if len(sys.argv) > 5 else 0
            result = reveal_from_video(sys.argv[2], sys.argv[3], sys.argv[4], fi)

        else:
            result = {'success': False, 'error': f'Unknown command: {cmd}'}

        print(json.dumps(result), flush=True)

    except Exception as e:
        log(f'Fatal error in main: {str(e)}')
        print(json.dumps({'success': False, 'error': str(e)}), flush=True)

if __name__ == '__main__':
    main()