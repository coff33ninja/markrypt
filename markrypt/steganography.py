"""
Steganography module for Markrypt

Hide encrypted messages in images using LSB (Least Significant Bit) technique
"""

import os
import base64
import json
from .exceptions import MarkryptError

try:
    from PIL import Image
    import numpy as np
    STEGO_AVAILABLE = True
except ImportError:
    STEGO_AVAILABLE = False


class Steganography:
    """Steganography implementation for hiding messages in images"""
    
    def __init__(self):
        """Initialize steganography with required libraries"""
        if not STEGO_AVAILABLE:
            raise MarkryptError(
                "Steganography requires 'Pillow' and 'numpy' libraries. "
                "Install with: pip install markrypt[stego]"
            )
    
    def _text_to_binary(self, text):
        """Convert text to binary representation"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def _binary_to_text(self, binary):
        """Convert binary representation back to text"""
        chars = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    
    def _get_image_capacity(self, image_path):
        """Calculate maximum message capacity for an image"""
        try:
            with Image.open(image_path) as img:
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                width, height = img.size
                # Each pixel has 3 channels (RGB), we can use 1 bit per channel
                # Reserve some bits for metadata
                capacity_bits = (width * height * 3) - 64  # 64 bits reserved
                capacity_chars = capacity_bits // 8
                return capacity_chars
        except Exception as e:
            raise MarkryptError(f"Failed to analyze image capacity: {str(e)}")
    
    def hide_message_in_image(self, message, image_path, output_path, password=None):
        """
        Hide encrypted message in image using LSB steganography
        
        Args:
            message: The message to hide (should be encrypted)
            image_path: Path to cover image
            output_path: Path for output image with hidden message
            password: Optional password for additional security
            
        Returns:
            dict with operation details
        """
        try:
            # Check image capacity
            capacity = self._get_image_capacity(image_path)
            if len(message) > capacity:
                raise MarkryptError(f"Message too large for image. Max capacity: {capacity} chars, message: {len(message)} chars")
            
            # Open and prepare image
            with Image.open(image_path) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Prepare message with metadata
                metadata = {
                    'length': len(message),
                    'has_password': password is not None,
                    'version': 'v1'
                }
                
                if password:
                    # Simple password-based XOR (for demonstration)
                    password_hash = hash(password) % 256
                    message = ''.join(chr(ord(c) ^ password_hash) for c in message)
                
                # Add end marker
                full_message = json.dumps(metadata) + '|||' + message + '|||END'
                binary_message = self._text_to_binary(full_message)
                
                # Hide message in LSBs
                data_index = 0
                for i in range(height):
                    for j in range(width):
                        for k in range(channels):
                            if data_index < len(binary_message):
                                # Modify LSB
                                img_array[i, j, k] = (img_array[i, j, k] & 0xFE) | int(binary_message[data_index])
                                data_index += 1
                            else:
                                break
                        if data_index >= len(binary_message):
                            break
                    if data_index >= len(binary_message):
                        break
                
                # Save modified image
                result_img = Image.fromarray(img_array)
                result_img.save(output_path, quality=95)  # High quality to preserve data
                
                return {
                    'success': True,
                    'message_length': len(message),
                    'image_capacity': capacity,
                    'output_path': output_path,
                    'utilization': f"{(len(message) / capacity) * 100:.2f}%"
                }
                
        except Exception as e:
            raise MarkryptError(f"Failed to hide message in image: {str(e)}")
    
    def extract_message_from_image(self, image_path, password=None):
        """
        Extract hidden message from image
        
        Args:
            image_path: Path to image with hidden message
            password: Password if message was password-protected
            
        Returns:
            Extracted message
        """
        try:
            with Image.open(image_path) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Extract binary data from LSBs
                binary_data = ''
                for i in range(height):
                    for j in range(width):
                        for k in range(channels):
                            binary_data += str(img_array[i, j, k] & 1)
                
                # Convert to text and find end marker
                text_data = self._binary_to_text(binary_data)
                
                # Find metadata separator
                if '|||' not in text_data:
                    raise MarkryptError("No hidden message found or message corrupted")
                
                parts = text_data.split('|||')
                if len(parts) < 3:
                    raise MarkryptError("Invalid message format")
                
                try:
                    metadata = json.loads(parts[0])
                except:
                    raise MarkryptError("Corrupted message metadata")
                
                # Extract message
                message_part = parts[1]
                expected_length = metadata.get('length', len(message_part))
                message = message_part[:expected_length]
                
                # Decrypt with password if needed
                if metadata.get('has_password', False):
                    if not password:
                        raise MarkryptError("Password required to extract message")
                    
                    password_hash = hash(password) % 256
                    message = ''.join(chr(ord(c) ^ password_hash) for c in message)
                
                return message
                
        except Exception as e:
            raise MarkryptError(f"Failed to extract message from image: {str(e)}")
    
    def analyze_image_for_steganography(self, image_path):
        """
        Analyze image for steganography potential
        
        Returns:
            dict with analysis results
        """
        try:
            with Image.open(image_path) as img:
                original_mode = img.mode
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                width, height = img.size
                img_array = np.array(img)
                
                # Calculate statistics
                total_pixels = width * height
                total_bits = total_pixels * 3  # RGB channels
                capacity_chars = (total_bits - 64) // 8  # Reserve 64 bits for metadata
                
                # Analyze LSB randomness (simple test for existing steganography)
                lsb_data = []
                for i in range(min(1000, height)):  # Sample first 1000 rows
                    for j in range(width):
                        for k in range(3):
                            lsb_data.append(img_array[i, j, k] & 1)
                
                # Calculate LSB entropy (0.5 is random, closer to 0 or 1 suggests patterns)
                lsb_ones = sum(lsb_data)
                lsb_ratio = lsb_ones / len(lsb_data) if lsb_data else 0
                
                return {
                    'image_path': image_path,
                    'original_mode': original_mode,
                    'dimensions': f"{width}x{height}",
                    'total_pixels': total_pixels,
                    'capacity_chars': capacity_chars,
                    'capacity_kb': capacity_chars / 1024,
                    'lsb_ones_ratio': lsb_ratio,
                    'suspected_steganography': abs(lsb_ratio - 0.5) < 0.1,  # Very rough heuristic
                    'file_size_bytes': os.path.getsize(image_path)
                }
                
        except Exception as e:
            raise MarkryptError(f"Failed to analyze image: {str(e)}")
    
    def create_cover_image(self, width=800, height=600, pattern='random', output_path='cover.png'):
        """
        Create a cover image suitable for steganography
        
        Args:
            width: Image width
            height: Image height  
            pattern: Pattern type ('random', 'gradient', 'noise')
            output_path: Output file path
            
        Returns:
            Path to created image
        """
        try:
            if pattern == 'random':
                # Random colored pixels
                img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            elif pattern == 'gradient':
                # Gradient pattern
                img_array = np.zeros((height, width, 3), dtype=np.uint8)
                for i in range(height):
                    for j in range(width):
                        img_array[i, j] = [
                            int((i / height) * 255),
                            int((j / width) * 255),
                            int(((i + j) / (height + width)) * 255)
                        ]
            elif pattern == 'noise':
                # Perlin-like noise pattern
                img_array = np.random.normal(128, 30, (height, width, 3)).astype(np.uint8)
                img_array = np.clip(img_array, 0, 255)
            else:
                raise MarkryptError(f"Unknown pattern: {pattern}")
            
            img = Image.fromarray(img_array)
            img.save(output_path)
            
            return output_path
            
        except Exception as e:
            raise MarkryptError(f"Failed to create cover image: {str(e)}")


def create_steganography_instance():
    """Factory function to create Steganography instance with error handling"""
    try:
        return Steganography()
    except MarkryptError as e:
        print(f"Warning: {e}")
        return None