import numpy as np
from PIL import Image
import sys
import json
import math

def log(message):
    """Safe logging to stderr to prevent JSON corruption"""
    print(message, file=sys.stderr, flush=True)

def calculate_all_metrics(original_path, encrypted_path):
    """Calculate all security metrics safely between image and binary file"""
    
    # 1. Load original image
    original = Image.open(original_path)
    orig_array = np.array(original)
    flat_orig = orig_array.flatten().astype(np.float64)
    
    # 2. Load encrypted binary data securely
    with open(encrypted_path, 'rb') as f:
        enc_data = np.frombuffer(f.read(), dtype=np.uint8)
    flat_enc = enc_data.flatten().astype(np.float64)
    
    # 3. Match lengths for mathematical comparison
    min_len = min(len(flat_orig), len(flat_enc))
    if min_len == 0:
        raise ValueError("One of the files is empty.")
        
    f1 = flat_orig[:min_len]
    f2 = flat_enc[:min_len]
    
    total_pixels = min_len
    
    # NPCR
    diff_pixels = np.sum(f1 != f2)
    npcr = (diff_pixels / total_pixels) * 100.0
    
    # UACI
    uaci = (np.sum(np.abs(f1 - f2)) / (total_pixels * 255.0)) * 100.0
    
    # MSE
    mse = np.mean((f1 - f2) ** 2)
    
    # PSNR
    if mse == 0:
        psnr = float('inf')
    else:
        psnr = 10 * math.log10((255.0 ** 2) / mse)
        
    # Correlation (Horizontal) - sample to prevent memory exhaustion on large files
    if total_pixels > 10000:
        indices = np.random.choice(total_pixels - 1, 10000, replace=False)
    else:
        indices = np.arange(total_pixels - 1)
        
    x = f2[indices]
    y = f2[indices + 1]
    
    # Protect against NaN errors if data is perfectly uniform
    if np.std(x) == 0 or np.std(y) == 0:
        correlation = 0.0
    else:
        corr = np.corrcoef(x, y)[0, 1]
        correlation = abs(float(corr)) if not np.isnan(corr) else 0.0
        
    # Key Space (AES-256)
    key_space = 256  # 2^256 represented as power
    
    return {
        'npcr': round(npcr, 2),
        'uaci': round(uaci, 2),
        'mse': round(mse, 2),
        'psnr': round(psnr, 2) if psnr != float('inf') else "inf",
        'correlation': round(correlation, 4),
        'key_space': key_space
    }

if __name__ == '__main__':
    # Ensure ONLY JSON is printed to stdout
    try:
        if len(sys.argv) >= 3:
            metrics = calculate_all_metrics(sys.argv[1], sys.argv[2])
            print(json.dumps({
                "success": True, 
                "metrics": metrics
            }))
        else:
            print(json.dumps({
                "success": False, 
                "error": "Usage: python calculate_metrics.py <original> <encrypted>"
            }))
    except Exception as e:
        log(f"Error: {str(e)}")
        print(json.dumps({
            "success": False,
            "error": str(e)
        }))