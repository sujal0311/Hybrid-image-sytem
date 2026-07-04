import numpy as np
from PIL import Image
import sys
import hashlib

def log(msg):
    """Safe logging to stderr"""
    print(msg, file=sys.stderr, flush=True)

def derive_chaotic_seed(key_str: str) -> float:
    """Derive a stable chaotic initial condition from the encryption key."""
    if not key_str:
        return 0.5000
    h = hashlib.sha256(str(key_str).encode("utf-8")).digest()
    val = int.from_bytes(h[:8], "big")
    seed = val / (2**64 - 1)
    # Prevent degenerate seeds
    if seed < 0.0001: seed = 0.0001
    elif seed > 0.9999: seed = 0.9999
    return seed

# ── Chaotic Sequence Generators ───────────────────────────────────────────────

def generate_permutation(total_pixels, map_type='logistic', seed=0.5):
    """
    Generates a guaranteed 1-to-1 permutation array using chaotic maps.
    Using np.zeros instead of .append() makes this ~50x faster.
    """
    vals = np.zeros(total_pixels, dtype=np.float64)
    
    if map_type == 'tent':
        x = seed
        for i in range(total_pixels):
            x = 2 * x if x < 0.5 else 2 * (1 - x)
            vals[i] = x
            
    elif map_type == 'henon':
        x, y = seed, seed
        for i in range(total_pixels):
            x_new = 1 - 1.4 * x**2 + y
            y = 0.3 * x
            x = x_new
            vals[i] = abs(x)
            
    elif map_type == 'arnold':
        # Simulated 1D chaotic mapping for Arnold to guarantee no data loss.
        # Standard 2D Arnold map on non-square float grids causes pixel collisions.
        x, y = seed, seed
        for i in range(total_pixels):
            x_new = (x + y) % 1
            y_new = (x + 2 * y) % 1
            x, y = x_new, y_new
            vals[i] = x + y
            
    else: # Default: logistic
        x = seed
        for i in range(total_pixels):
            x = 3.99 * x * (1 - x)
            vals[i] = x

    # argsort guarantees a perfect, collision-free 1-to-1 permutation
    return np.argsort(vals)

# ── Forward & Reverse Scrambling ──────────────────────────────────────────────

def apply_chaotic_scramble(img_array, key='default', map_type='logistic', iterations=1):
    """
    Apply chaotic scrambling to image pixels using a key-derived seed.
    """
    try:
        flat_img = img_array.flatten()
        total_pixels = len(flat_img)
        
        # 1. Derive seed from key
        seed = derive_chaotic_seed(key)
        
        # 2. Generate perfect permutation
        perm = generate_permutation(total_pixels, map_type, seed)
        
        # 3. Apply scramble
        scrambled_flat = flat_img[perm]
        
        # 4. Reshape back
        return scrambled_flat.reshape(img_array.shape).astype(np.uint8)
        
    except Exception as e:
        log(f"Error in chaotic scrambling: {e}")
        return img_array

def reverse_chaotic_scramble(scrambled_array, key='default', map_type='logistic', iterations=1):
    """
    Reverse the chaotic scrambling to get original image.
    Works universally for ALL maps by recreating the exact same permutation.
    """
    try:
        flat_scrambled = scrambled_array.flatten()
        total_pixels = len(flat_scrambled)
        
        # 1. Derive the SAME seed from the key
        seed = derive_chaotic_seed(key)
        
        # 2. Generate the SAME permutation
        perm = generate_permutation(total_pixels, map_type, seed)
        
        # 3. Reverse the scramble mapping
        original_flat = np.zeros_like(flat_scrambled)
        original_flat[perm] = flat_scrambled
        
        # 4. Reshape back
        return original_flat.reshape(scrambled_array.shape).astype(np.uint8)
        
    except Exception as e:
        log(f"Error in reverse scrambling: {e}")
        return scrambled_array

# ── Visualization Helper ──────────────────────────────────────────────────────

def visualize_scrambling(image_path, output_path, key='secret123', map_type='logistic'):
    """Helper function to visualize scrambling effect"""
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        
        scrambled = apply_chaotic_scramble(img_array, key, map_type)
        
        Image.fromarray(scrambled).save(output_path)
        print(f"Scrambled image saved to {output_path}")
    except Exception as e:
        print(f"Visualization failed: {e}")