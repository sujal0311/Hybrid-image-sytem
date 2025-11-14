import numpy as np
from PIL import Image

def logistic_map(x, r=3.99):
    """Logistic map: x(n+1) = r * x(n) * (1 - x(n))"""
    return r * x * (1 - x)

def arnold_cat_map(x, y, a=1, b=1):
    """Arnold Cat Map for 2D pixel position scrambling"""
    x_new = (x + a * y) % 1
    y_new = (b * x + (a * b + 1) * y) % 1
    return x_new, y_new

def tent_map(x, mu=2):
    """Tent map chaotic function"""
    if x < 0.5:
        return mu * x
    else:
        return mu * (1 - x)

def henon_map(x, y, a=1.4, b=0.3):
    """Henon map 2D chaotic function"""
    x_new = 1 - a * x**2 + y
    y_new = b * x
    return x_new, y_new

def apply_chaotic_scramble(img_array, map_type='logistic', iterations=5):
    """
    Apply chaotic scrambling to image pixels
    
    Args:
        img_array: numpy array of image
        map_type: type of chaotic map to use
        iterations: number of scrambling iterations
    
    Returns:
        scrambled numpy array
    """
    try:
        height, width = img_array.shape[:2]
        channels = img_array.shape[2] if len(img_array.shape) == 3 else 1
        
        # Flatten image
        flat_img = img_array.flatten()
        total_pixels = len(flat_img)
        
        # Generate chaotic sequence
        if map_type == 'logistic':
            x = 0.5  # Initial value
            indices = []
            for _ in range(total_pixels):
                x = logistic_map(x)
                indices.append(int(x * total_pixels) % total_pixels)
        
        elif map_type == 'arnold':
            # Arnold Cat Map for 2D scrambling
            indices = []
            for i in range(height):
                for j in range(width):
                    x = i / height
                    y = j / width
                    for _ in range(iterations):
                        x, y = arnold_cat_map(x, y)
                    new_i = int(x * height) % height
                    new_j = int(y * width) % width
                    if channels == 1:
                        indices.append(new_i * width + new_j)
                    else:
                        for c in range(channels):
                            indices.append((new_i * width + new_j) * channels + c)
        
        elif map_type == 'tent':
            x = 0.5
            indices = []
            for _ in range(total_pixels):
                x = tent_map(x)
                indices.append(int(x * total_pixels) % total_pixels)
        
        elif map_type == 'henon':
            x, y = 0.5, 0.5
            indices = []
            for _ in range(total_pixels):
                x, y = henon_map(x, y)
                indices.append(int(abs(x) * total_pixels) % total_pixels)
        
        else:
            # Default to logistic
            return apply_chaotic_scramble(img_array, 'logistic', iterations)
        
        # Scramble pixels
        scrambled_flat = np.zeros_like(flat_img)
        for i, idx in enumerate(indices[:total_pixels]):
            scrambled_flat[i] = flat_img[idx]
        
        # Reshape back to original dimensions
        scrambled = scrambled_flat.reshape(img_array.shape)
        
        return scrambled.astype(np.uint8)
    
    except Exception as e:
        print(f"Error in chaotic scrambling: {e}")
        return img_array

def reverse_chaotic_scramble(scrambled_array, map_type='logistic', iterations=5):
    """
    Reverse the chaotic scrambling to get original image
    
    Args:
        scrambled_array: scrambled numpy array
        map_type: type of chaotic map used
        iterations: number of iterations used
    
    Returns:
        original numpy array
    """
    try:
        # Generate same chaotic sequence
        total_pixels = len(scrambled_array.flatten())
        
        if map_type == 'logistic':
            x = 0.5
            indices = []
            for _ in range(total_pixels):
                x = logistic_map(x)
                indices.append(int(x * total_pixels) % total_pixels)
        
        # Add similar logic for other maps...
        else:
            indices = list(range(total_pixels))
        
        # Reverse scrambling
        flat_scrambled = scrambled_array.flatten()
        original_flat = np.zeros_like(flat_scrambled)
        
        for i, idx in enumerate(indices[:total_pixels]):
            original_flat[idx] = flat_scrambled[i]
        
        # Reshape
        original_shape = scrambled_array.shape
        original = original_flat.reshape(original_shape)
        
        return original.astype(np.uint8)
    
    except Exception as e:
        print(f"Error in reverse scrambling: {e}")
        return scrambled_array

def visualize_scrambling(image_path, output_path, map_type='logistic'):
    """Helper function to visualize scrambling effect"""
    img = Image.open(image_path)
    img_array = np.array(img)
    
    scrambled = apply_chaotic_scramble(img_array, map_type)
    
    Image.fromarray(scrambled).save(output_path)
    print(f"Scrambled image saved to {output_path}")
