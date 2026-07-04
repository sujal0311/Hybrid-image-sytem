import numpy as np
from PIL import Image
import sys
import json
import os
import math

# ── Safe Logging ──────────────────────────────────────────────────────────────
def log(message):
    """Log to stderr to prevent corrupting JSON stdout"""
    print(message, file=sys.stderr, flush=True)

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0.0
    hist, _ = np.histogram(data.flatten(), bins=256, range=(0, 256))
    hist = hist[hist > 0]
    hist = hist / hist.sum()
    entropy = -np.sum(hist * np.log2(hist))
    return float(entropy)

def calculate_npcr_uaci(img1_array, img2_array):
    """Calculate NPCR and UACI securely between two flat arrays"""
    # Ensure flat 1D arrays for comparison
    flat1 = img1_array.flatten().astype(np.float64)
    flat2 = img2_array.flatten().astype(np.float64)

    min_len = min(len(flat1), len(flat2))
    if min_len == 0:
        return 0.0, 0.0
        
    f1 = flat1[:min_len]
    f2 = flat2[:min_len]

    # NPCR
    diff = (f1 != f2).astype(np.float64)
    npcr = (np.sum(diff) / min_len) * 100.0

    # UACI
    abs_diff = np.abs(f1 - f2)
    uaci = (np.sum(abs_diff) / (min_len * 255.0)) * 100.0

    return float(npcr), float(uaci)

def calculate_mse_psnr(orig, stego):
    """Calculate MSE and PSNR"""
    if orig.shape != stego.shape:
        log(f"Shape mismatch in PSNR: {orig.shape} vs {stego.shape}. Forcing resize.")
        stego_img = Image.fromarray(stego).resize((orig.shape[1], orig.shape[0]))
        stego = np.array(stego_img)

    mse = np.mean((orig.astype(np.float64) - stego.astype(np.float64)) ** 2)

    if mse == 0:
        psnr = float('inf')
    else:
        psnr = 20 * math.log10(255.0 / math.sqrt(mse))

    return float(mse), float(psnr)

def calculate_correlation(img_array, direction='horizontal'):
    """Calculate correlation coefficient with NaN protection"""
    if len(img_array.shape) == 3:
        img_array = np.mean(img_array, axis=2).astype(np.uint8)
    
    if direction == 'horizontal' and img_array.shape[1] > 1:
        x = img_array[:, :-1].flatten()
        y = img_array[:, 1:].flatten()
    elif img_array.shape[0] > 1:
        x = img_array[:-1, :].flatten()
        y = img_array[1:, :].flatten()
    else:
        return 0.0
    
    # Sample for performance if the image is massive
    if len(x) > 10000:
        indices = np.random.choice(len(x), 10000, replace=False)
        x, y = x[indices], y[indices]
    
    if len(x) < 2:
        return 0.0
        
    # Prevent division by zero / NaN errors in perfectly uniform data
    if np.std(x) == 0 or np.std(y) == 0:
        return 0.0
    
    corr = np.corrcoef(x, y)[0, 1]
    return float(corr) if not np.isnan(corr) else 0.0

def analyze_encryption(original_path, encrypted_path):
    """Analyze encryption quality"""
    try:
        log(f"Analyzing encryption: {original_path} vs {encrypted_path}")
        original_img = Image.open(original_path)
        original_array = np.array(original_img)
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = np.frombuffer(f.read(), dtype=np.uint8)
        
        original_entropy = calculate_entropy(original_array)
        encrypted_entropy = calculate_entropy(encrypted_data)
        
        npcr, uaci = calculate_npcr_uaci(original_array, encrypted_data)
        
        # Correlation of encrypted data (sample a block to avoid memory exhaustion)
        if len(encrypted_data) >= 65536:
            sample = encrypted_data[:65536].reshape(256, 256)
            encrypted_corr = calculate_correlation(sample)
        else:
            side = int(math.sqrt(len(encrypted_data)))
            if side > 1:
                sample = encrypted_data[:side*side].reshape(side, side)
                encrypted_corr = calculate_correlation(sample)
            else:
                encrypted_corr = 0.0
        
        return {
            'success': True,
            'entropy': {
                'original': round(original_entropy, 4),
                'encrypted': round(encrypted_entropy, 4)
            },
            'npcr': round(npcr, 2),
            'uaci': round(uaci, 2),
            'correlation': {
                'encrypted': round(encrypted_corr, 6)
            }
        }
    except Exception as e:
        log(f"Encryption analysis error: {str(e)}")
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

def analyze_steganography(original_path, stego_path):
    """Analyze steganography quality"""
    try:
        log(f"Analyzing steganography: {original_path} vs {stego_path}")
        original_img = Image.open(original_path)
        stego_img = Image.open(stego_path)
        
        original_array = np.array(original_img)
        stego_array = np.array(stego_img)
        
        mse, psnr = calculate_mse_psnr(original_array, stego_array)
        
        return {
            'success': True,
            'mse': round(mse, 4),
            'psnr': round(psnr, 2) if psnr != float('inf') else "inf"
        }
    except Exception as e:
        log(f"Steganography analysis error: {str(e)}")
        import traceback; traceback.print_exc(file=sys.stderr)
        return {'success': False, 'error': str(e)}

def main():
    try:
        if len(sys.argv) < 2:
            print(json.dumps({'success': False, 'error': 'No command specified'}))
            sys.exit(1)
        
        command = sys.argv[1]
        
        if command == 'encryption' and len(sys.argv) >= 4:
            result = analyze_encryption(sys.argv[2], sys.argv[3])
        elif command == 'steganography' and len(sys.argv) >= 4:
            result = analyze_steganography(sys.argv[2], sys.argv[3])
        else:
            result = {'success': False, 'error': 'Invalid arguments'}
            
        print(json.dumps(result), flush=True)
        
    except Exception as e:
        log(f"Fatal error in main: {str(e)}")
        print(json.dumps({'success': False, 'error': str(e)}), flush=True)

if __name__ == '__main__':
    main()