import numpy as np
from PIL import Image
import sys
import json
import os

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0.0
    hist, _ = np.histogram(data.flatten(), bins=256, range=(0, 256))
    hist = hist[hist > 0]
    hist = hist / hist.sum()
    entropy = -np.sum(hist * np.log2(hist))
    return float(entropy)

def calculate_npcr_uaci(img1, img2):
    """Calculate NPCR and UACI between two images"""
    if img1.shape != img2.shape:
        return 0.0, 0.0
    
    # NPCR
    diff = (img1 != img2).astype(int)
    npcr = (np.sum(diff) / diff.size) * 100
    
    # UACI
    abs_diff = np.abs(img1.astype(float) - img2.astype(float))
    uaci = (np.sum(abs_diff) / (diff.size * 255)) * 100
    
    return float(npcr), float(uaci)

def calculate_mse_psnr(img1, img2):
    """Calculate MSE and PSNR"""
    if img1.shape != img2.shape:
        return 0.0, 0.0
    
    mse = np.mean((img1.astype(float) - img2.astype(float)) ** 2)
    
    if mse == 0:
        psnr = 100.0
    else:
        psnr = 20 * np.log10(255.0 / np.sqrt(mse))
    
    return float(mse), float(psnr)

def calculate_correlation(img, direction='horizontal'):
    """Calculate correlation coefficient"""
    if len(img.shape) == 3:
        img = np.mean(img, axis=2).astype(np.uint8)
    
    if direction == 'horizontal' and img.shape[1] > 1:
        x = img[:, :-1].flatten()
        y = img[:, 1:].flatten()
    elif img.shape[0] > 1:
        x = img[:-1, :].flatten()
        y = img[1:, :].flatten()
    else:
        return 0.0
    
    # Sample for performance
    if len(x) > 5000:
        indices = np.random.choice(len(x), 5000, replace=False)
        x, y = x[indices], y[indices]
    
    if len(x) < 2:
        return 0.0
    
    return float(np.corrcoef(x, y)[0, 1])

def analyze_encryption(original_path, encrypted_path):
    """Analyze encryption quality"""
    try:
        # Load original image
        original_img = Image.open(original_path)
        original_array = np.array(original_img)
        
        # Load encrypted data (binary file)
        with open(encrypted_path, 'rb') as f:
            encrypted_data = np.frombuffer(f.read(), dtype=np.uint8)
        
        # Calculate metrics
        original_entropy = calculate_entropy(original_array)
        encrypted_entropy = calculate_entropy(encrypted_data)
        
        # For NPCR/UACI, compare original with encrypted (resized to match)
        flat_original = original_array.flatten()
        min_len = min(len(flat_original), len(encrypted_data))
        npcr, uaci = calculate_npcr_uaci(
            flat_original[:min_len].reshape(-1, 1),
            encrypted_data[:min_len].reshape(-1, 1)
        )
        
        # Correlation of encrypted data
        if len(encrypted_data) >= 100:
            sample = encrypted_data[:100].reshape(10, 10)
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
        return {'success': False, 'error': str(e)}

def analyze_steganography(original_path, stego_path):
    """Analyze steganography quality"""
    try:
        original_img = Image.open(original_path)
        stego_img = Image.open(stego_path)
        
        original_array = np.array(original_img)
        stego_array = np.array(stego_img)
        
        mse, psnr = calculate_mse_psnr(original_array, stego_array)
        
        return {
            'success': True,
            'mse': round(mse, 4),
            'psnr': round(psnr, 2)
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No command specified'}))
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'encryption' and len(sys.argv) == 4:
        result = analyze_encryption(sys.argv[2], sys.argv[3])
        print(json.dumps(result))
    elif command == 'steganography' and len(sys.argv) == 4:
        result = analyze_steganography(sys.argv[2], sys.argv[3])
        print(json.dumps(result))
    else:
        print(json.dumps({'error': 'Invalid arguments'}))
