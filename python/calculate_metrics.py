import numpy as np
from PIL import Image
import sys

def calculate_all_metrics(original_path, encrypted_path):
    """Calculate all security metrics"""
    
    # Load images
    original = Image.open(original_path)
    encrypted = Image.open(encrypted_path)
    
    # Convert to numpy arrays
    orig_array = np.array(original)
    enc_array = np.array(encrypted)
    
    # 1. NPCR
    diff_pixels = np.sum(orig_array != enc_array)
    total_pixels = orig_array.size
    npcr = (diff_pixels / total_pixels) * 100
    
    # 2. UACI
    uaci = (np.sum(np.abs(orig_array.astype(float) - enc_array.astype(float))) / (total_pixels * 255)) * 100
    
    # 3. MSE
    mse = np.mean((orig_array.astype(float) - enc_array.astype(float)) ** 2)
    
    # 4. PSNR
    if mse == 0:
        psnr = 100
    else:
        psnr = 10 * np.log10((255 ** 2) / mse)
    
    # 5. Correlation (horizontal)
    x = orig_array[:, :-1].flatten()
    y = orig_array[:, 1:].flatten()
    correlation = abs(np.corrcoef(x, y)[0, 1])
    
    # 6. Key Space (AES-256)
    key_space = 256  # 2^256 represented as power
    
    return {
        'npcr': round(npcr, 2),
        'uaci': round(uaci, 2),
        'mse': round(mse, 2),
        'psnr': round(psnr, 2),
        'correlation': round(correlation, 4),
        'key_space': key_space
    }

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        metrics = calculate_all_metrics(sys.argv[1], sys.argv[2])
        print("Security Metrics:")
        print(f"NPCR: {metrics['npcr']}%")
        print(f"UACI: {metrics['uaci']}%")
        print(f"MSE: {metrics['mse']}")
        print(f"PSNR: {metrics['psnr']} dB")
        print(f"Correlation: {metrics['correlation']}")
        print(f"Key Space: 2^{metrics['key_space']}")
    else:
        print("Usage: python calculate_metrics.py <original> <encrypted>")
