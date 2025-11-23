import re
import math
import zlib
import base64
import numpy as np
from collections import Counter
from scipy import stats
import binascii

# def advanced_hash_features(hash_string):
#     """
#     Extract 80+ cryptographic features from hash string
#     Enhanced with robust byte conversion, advanced statistical analysis, 
#     and comprehensive algorithm detection
#     """
#     if not isinstance(hash_string, str):
#         hash_string = str(hash_string)
    
#     features = {}
#     length = len(hash_string)
    
#     # Convert to bytes with robust encoding detection
#     hash_bytes, encoding_type = robust_string_to_bytes(hash_string)
    
#     # ===== LAYER 1: Basic Character & Structural Features =====
#     features.update(basic_structural_features(hash_string, length))
#     features['detected_encoding'] = encoding_type
    
#     # ===== LAYER 2: Byte-Level Statistical Analysis =====
#     if len(hash_bytes) > 0:
#         features.update(byte_statistical_features(hash_bytes))
    
#     # ===== LAYER 3: Bit-Level Distribution Analysis =====
#     if len(hash_bytes) > 0:
#         features.update(bit_distribution_features(hash_bytes))
    
#     # ===== LAYER 4: Cryptographic Property Tests =====
#     if len(hash_bytes) > 0:
#         features.update(cryptographic_property_features(hash_bytes, hash_string))
    
#     # ===== LAYER 5: Encoding & Format Detection =====
#     features.update(encoding_format_features(hash_string, hash_bytes))
    
#     # ===== LAYER 6: Algorithm-Specific Patterns =====
#     features.update(algorithm_specific_features(hash_string, hash_bytes, length))
    
#     # ===== LAYER 7: Advanced Cryptographic Analysis =====
#     if len(hash_bytes) > 0:
#         features.update(advanced_crypto_analysis(hash_bytes, hash_string))
    
#     return features

def advanced_hash_features(hash_string):
    """
    Extract 100+ cryptographic features from hash string
    Enhanced with comprehensive MCF format detection
    """
    if not isinstance(hash_string, str):
        hash_string = str(hash_string)
    
    features = {}
    length = len(hash_string)
    
    # ===== LAYER 0: MCF-SPECIFIC FEATURES =====
    mcf_features = extract_mcf_specific_features(hash_string)
    features.update(mcf_features)
    
    # Determine what to analyze based on MCF detection
    analysis_target = hash_string
    if mcf_features['is_mcf_hash'] and mcf_features.get('mcf_hash_component_length', 0) > 0:
        # Analyze only the hash component for MCF formats
        mcf_info = detect_mcf_format(hash_string)
        analysis_target = mcf_info['hash_value'] if mcf_info else hash_string
    
    # Convert to bytes with robust encoding detection
    hash_bytes, encoding_type = robust_string_to_bytes(analysis_target)
    
    # ===== LAYER 1: Basic Character & Structural Features =====
    features.update(basic_structural_features(hash_string, length))  # Use original string for structural analysis
    features['detected_encoding'] = encoding_type
    
    # ===== LAYER 2: Byte-Level Statistical Analysis =====
    if len(hash_bytes) > 0:
        features.update(byte_statistical_features(hash_bytes))
    
    # ===== LAYER 3: Bit-Level Distribution Analysis =====
    if len(hash_bytes) > 0:
        features.update(bit_distribution_features(hash_bytes))
    
    # ===== LAYER 4: Cryptographic Property Tests =====
    if len(hash_bytes) > 0:
        features.update(cryptographic_property_features(hash_bytes, hash_string))
    
    # ===== LAYER 5: Encoding & Format Detection =====
    features.update(encoding_format_features(hash_string, hash_bytes))
    
    # ===== LAYER 6: Algorithm-Specific Patterns =====
    features.update(algorithm_specific_features(hash_string, hash_bytes, length))
    
    # ===== LAYER 7: Advanced Cryptographic Analysis =====
    if len(hash_bytes) > 0:
        features.update(advanced_crypto_analysis(hash_bytes, hash_string))
    
    return features


# ===== LAYER 0: MCF FORMAT DETECTION & PARSING =====
def detect_mcf_format(hash_string):
    """Comprehensive MCF (Modular Crypt Format) detection and parsing"""
    if not hash_string.startswith('$'):
        return None
    
    parts = hash_string.split('$')
    if len(parts) < 4:
        return None
    
    mcf_id = parts[1]
    mcf_map = {
        "1": "MD5-crypt", 
        "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt",
        "5": "SHA256-crypt", "6": "SHA512-crypt", 
        "argon2i": "Argon2i", "argon2d": "Argon2d", "argon2id": "Argon2id",
        "scrypt": "scrypt", "y": "yescrypt",
        "8": "Cisco8", "9": "Cisco9",
        "pbkdf2-sha256": "PBKDF2-SHA256", "pbkdf2-sha1": "PBKDF2-SHA1"
    }
    
    algorithm = mcf_map.get(mcf_id, "unknown_mcf")
    
    # Parse parameters based on algorithm type
    parameters = parts[2] if len(parts) > 2 else None
    salt = parts[3] if len(parts) > 3 else None
    hash_value = parts[4] if len(parts) > 4 else None
    
    # Extract specific parameters
    param_dict = {}
    if parameters:
        if algorithm == "bcrypt":
            param_dict["cost"] = int(parameters[:2]) if parameters[:2].isdigit() else 0
        elif algorithm.startswith("argon2"):
            # Parse: v=19$m=65536,t=3,p=4
            param_parts = parameters.split(',')
            for param in param_parts:
                if '=' in param:
                    key, value = param.split('=')
                    param_dict[key.strip()] = value.strip()
    
    return {
        'is_mcf': True,
        'mcf_id': mcf_id,
        'algorithm': algorithm,
        'parts_count': len(parts),
        'parameters': parameters,
        'salt': salt,
        'hash_value': hash_value,
        'param_dict': param_dict,
        'salt_length': len(salt) if salt else 0,
        'hash_component_length': len(hash_value) if hash_value else 0
    }

def extract_mcf_specific_features(hash_string):
    """Extract comprehensive MCF-specific features"""
    features = {}
    mcf_info = detect_mcf_format(hash_string)
    
    if mcf_info:
        features.update({
            'is_mcf_hash': 1,
            'mcf_parts_count': mcf_info['parts_count'],
            'mcf_has_parameters': int(mcf_info['parameters'] is not None),
            'mcf_has_salt': int(mcf_info['salt'] is not None),
            'mcf_salt_length': mcf_info['salt_length'],
            'mcf_hash_component_length': mcf_info['hash_component_length'],
            'mcf_algorithm_id_length': len(mcf_info['mcf_id']),
        })
        
        # Algorithm-specific flags
        algorithm_flags = {
            'is_bcrypt': mcf_info['algorithm'] == 'bcrypt',
            'is_argon2': mcf_info['algorithm'].startswith('argon2'),
            'is_argon2id': mcf_info['algorithm'] == 'Argon2id',
            'is_argon2i': mcf_info['algorithm'] == 'Argon2i', 
            'is_argon2d': mcf_info['algorithm'] == 'Argon2d',
            'is_md5_crypt': mcf_info['algorithm'] == 'MD5-crypt',
            'is_sha256_crypt': mcf_info['algorithm'] == 'SHA256-crypt',
            'is_sha512_crypt': mcf_info['algorithm'] == 'SHA512-crypt',
            'is_scrypt': mcf_info['algorithm'] == 'scrypt',
            'is_yescrypt': mcf_info['algorithm'] == 'yescrypt',
            'is_cisco_type8': mcf_info['algorithm'] == 'Cisco8',
            'is_cisco_type9': mcf_info['algorithm'] == 'Cisco9',
            'is_pbkdf2': 'pbkdf2' in mcf_info['algorithm'].lower(),
        }
        
        for flag_name, flag_value in algorithm_flags.items():
            features[flag_name] = int(flag_value)
        
        # Parameter-based features
        if mcf_info['param_dict']:
            if 'cost' in mcf_info['param_dict']:
                features['bcrypt_cost_factor'] = mcf_info['param_dict']['cost']
            if 'm' in mcf_info['param_dict']:
                features['argon2_memory'] = int(mcf_info['param_dict']['m'])
            if 't' in mcf_info['param_dict']:
                features['argon2_iterations'] = int(mcf_info['param_dict']['t'])
            if 'p' in mcf_info['param_dict']:
                features['argon2_parallelism'] = int(mcf_info['param_dict']['p'])
            if 'v' in mcf_info['param_dict']:
                features['argon2_version'] = int(mcf_info['param_dict']['v'])
        
        # Encoding patterns in MCF components
        if mcf_info['salt']:
            features['mcf_salt_is_hex'] = int(bool(re.match(r'^[a-fA-F0-9]+$', mcf_info['salt'])))
            features['mcf_salt_is_b64'] = int(bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', mcf_info['salt'])))
        
        if mcf_info['hash_value']:
            features['mcf_hash_is_hex'] = int(bool(re.match(r'^[a-fA-F0-9]+$', mcf_info['hash_value'])))
            features['mcf_hash_is_b64'] = int(bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', mcf_info['hash_value'])))
            
    else:
        # Non-MCF hash features
        features.update({
            'is_mcf_hash': 0,
            'mcf_parts_count': 0,
            'mcf_has_parameters': 0,
            'mcf_has_salt': 0,
            'mcf_salt_length': 0,
            'mcf_hash_component_length': 0,
            'mcf_algorithm_id_length': 0,
            'is_bcrypt': 0, 'is_argon2': 0, 'is_argon2id': 0, 'is_argon2i': 0, 'is_argon2d': 0,
            'is_md5_crypt': 0, 'is_sha256_crypt': 0, 'is_sha512_crypt': 0, 'is_scrypt': 0,
            'is_yescrypt': 0, 'is_cisco_type8': 0, 'is_cisco_type9': 0, 'is_pbkdf2': 0,
            'bcrypt_cost_factor': 0, 'argon2_memory': 0, 'argon2_iterations': 0, 
            'argon2_parallelism': 0, 'argon2_version': 0,
            'mcf_salt_is_hex': 0, 'mcf_salt_is_b64': 0, 'mcf_hash_is_hex': 0, 'mcf_hash_is_b64': 0
        })
    
    return features

def robust_string_to_bytes(hash_string):
    """
    Robust byte conversion with multiple fallback strategies
    Returns: (bytes_data, encoding_type)
    """
    encoding_type = "unknown"
    
    # Empty string case
    if not hash_string:
        return b'', encoding_type
    
    # Strategy 1: Hex decoding (handle odd-length hex)
    if re.match(r'^[a-fA-F0-9]+$', hash_string):
        encoding_type = "hex"
        try:
            # Handle odd-length hex by padding with '0'
            if len(hash_string) % 2 != 0:
                hash_string = '0' + hash_string  # Pad at beginning to preserve alignment
            return bytes.fromhex(hash_string), encoding_type
        except Exception as e:
            pass  # Fall through to other methods
    
    # Strategy 2: Base64 decoding
    base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
    if re.match(base64_pattern, hash_string):
        encoding_type = "base64"
        try:
            # Add padding if needed
            padding_needed = (4 - len(hash_string) % 4) % 4
            padded_string = hash_string + '=' * padding_needed
            return base64.b64decode(padded_string), encoding_type
        except Exception as e:
            pass
    
    # Strategy 3: Base64 URL-safe decoding
    base64url_pattern = r'^[A-Za-z0-9_-]*$'
    if re.match(base64url_pattern, hash_string):
        encoding_type = "base64url"
        try:
            # Convert to standard base64
            standard_b64 = hash_string.replace('-', '+').replace('_', '/')
            padding_needed = (4 - len(standard_b64) % 4) % 4
            padded_string = standard_b64 + '=' * padding_needed
            return base64.b64decode(padded_string), encoding_type
        except Exception as e:
            pass
    
    # Strategy 4: Check for common hash formats with special prefixes
    if hash_string.startswith(('$2a$', '$2b$', '$2y$', '$1$', '$5$', '$6$')):
        encoding_type = "crypt_format"
        # For crypt formats, use the entire string as bytes
        return hash_string.encode('utf-8'), encoding_type
    
    # Strategy 5: UTF-8 fallback with validation
    encoding_type = "utf8"
    try:
        utf8_bytes = hash_string.encode('utf-8')
        # Check if it's valid UTF-8 by decoding back
        hash_string.encode('utf-8').decode('utf-8')
        return utf8_bytes, encoding_type
    except:
        # Final fallback: latin-1 which never fails
        encoding_type = "latin1"
        return hash_string.encode('latin-1'), encoding_type

def basic_structural_features(hash_string, length):
    """Enhanced basic character-level and structural features"""
    chars = list(hash_string)
    features = {}
    
    # Basic characteristics
    features['length'] = length
    features['is_hex'] = bool(re.match(r'^[a-fA-F0-9]+$', hash_string))
    features['has_symbols'] = bool(re.search(r'[^a-zA-Z0-9]', hash_string))
    features['is_alphanumeric'] = hash_string.isalnum()
    features['is_printable'] = all(c.isprintable() or c in '\t\n\r' for c in hash_string)
    
    # Character type counts
    features['digit_count'] = sum(c.isdigit() for c in chars)
    features['letter_count'] = sum(c.isalpha() for c in chars)
    features['uppercase_count'] = sum(c.isupper() for c in chars)
    features['lowercase_count'] = sum(c.islower() for c in chars)
    features['symbol_count'] = len([c for c in chars if not c.isalnum()])
    features['hex_lower_count'] = sum(1 for c in chars if c in 'abcdef')
    features['hex_upper_count'] = sum(1 for c in chars if c in 'ABCDEF')
    features['space_count'] = sum(c.isspace() for c in chars)
    
    # Advanced character distribution
    features['consecutive_repeated_chars'] = count_consecutive_repeats(hash_string)
    features['char_transitions'] = count_character_transitions(hash_string)
    
    # Ratios and densities
    features['digit_ratio'] = features['digit_count'] / max(1, length)
    features['letter_ratio'] = features['letter_count'] / max(1, length)
    features['uppercase_ratio'] = features['uppercase_count'] / max(1, max(1, features['letter_count']))
    features['lowercase_ratio'] = features['lowercase_count'] / max(1, max(1, features['letter_count']))
    features['symbol_ratio'] = features['symbol_count'] / max(1, length)
    features['hex_ratio'] = (features['hex_lower_count'] + features['hex_upper_count']) / max(1, length)
    features['space_ratio'] = features['space_count'] / max(1, length)
    
    # String entropy and complexity
    if length > 0:
        freq = Counter(chars)
        entropy = 0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        features['char_entropy'] = entropy
        features['unique_chars'] = len(freq)
        features['char_unique_ratio'] = len(freq) / length
        features['most_common_char_freq'] = max(freq.values()) / length if freq else 0
    else:
        features['char_entropy'] = 0
        features['unique_chars'] = 0
        features['char_unique_ratio'] = 0
        features['most_common_char_freq'] = 0
    
    return features

def count_consecutive_repeats(string):
    """Count consecutive repeated characters"""
    if not string:
        return 0
    repeats = 0
    current_char = string[0]
    current_count = 1
    
    for i in range(1, len(string)):
        if string[i] == current_char:
            current_count += 1
        else:
            if current_count > 1:
                repeats += current_count - 1
            current_char = string[i]
            current_count = 1
    
    if current_count > 1:
        repeats += current_count - 1
    
    return repeats

def count_character_transitions(string):
    """Count transitions between character types"""
    if len(string) < 2:
        return 0
    
    transitions = 0
    for i in range(1, len(string)):
        prev_type = get_char_type(string[i-1])
        curr_type = get_char_type(string[i])
        if prev_type != curr_type:
            transitions += 1
    
    return transitions

def get_char_type(char):
    """Categorize character type"""
    if char.isdigit():
        return 'digit'
    elif char.isupper():
        return 'upper'
    elif char.islower():
        return 'lower'
    elif char.isalnum():
        return 'alnum'
    else:
        return 'symbol'

# def byte_statistical_features(hash_bytes):
#     """Enhanced statistical analysis of byte values"""
#     features = {}
    
#     # FIX: Safe byte array conversion with proper error handling
#     try:
#         byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
#     except (ValueError, TypeError):
#         # Fallback: convert to list of byte values manually
#         byte_array = np.array([b for b in hash_bytes], dtype=np.uint8)
    
#     if len(byte_array) == 0:
#         # Return default values for empty arrays
#         features.update({
#             'byte_mean': 0.0, 'byte_std': 0.0, 'byte_variance': 0.0,
#             'byte_skewness': 0.0, 'byte_kurtosis': 0.0, 'byte_min': 0.0,
#             'byte_max': 0.0, 'byte_range': 0.0, 'byte_median': 0.0,
#             'byte_q1': 0.0, 'byte_q3': 0.0, 'byte_iqr': 0.0,
#             'byte_chi2_uniform': 0.0, 'byte_uniformity_pval': 0.0,
#             'byte_uniqueness_ratio': 0.0
#         })
#         return features
    
#     # Basic statistical moments with safe calculations
#     features['byte_mean'] = float(np.mean(byte_array))
#     features['byte_std'] = float(np.std(byte_array))
#     features['byte_variance'] = float(np.var(byte_array))
    
#     # Higher-order moments (if enough data)
#     if len(byte_array) > 1:
#         try:
#             features['byte_skewness'] = float(stats.skew(byte_array))
#             features['byte_kurtosis'] = float(stats.kurtosis(byte_array))
#         except:
#             features['byte_skewness'] = 0.0
#             features['byte_kurtosis'] = 0.0
#     else:
#         features['byte_skewness'] = 0.0
#         features['byte_kurtosis'] = 0.0
    
#     # Range and distribution
#     features['byte_min'] = float(np.min(byte_array))
#     features['byte_max'] = float(np.max(byte_array))
#     features['byte_range'] = features['byte_max'] - features['byte_min']
    
#     # Percentile analysis with safe calculation
#     try:
#         features['byte_median'] = float(np.median(byte_array))
#         features['byte_q1'] = float(np.percentile(byte_array, 25))
#         features['byte_q3'] = float(np.percentile(byte_array, 75))
#         features['byte_iqr'] = features['byte_q3'] - features['byte_q1']
#     except:
#         features['byte_median'] = features['byte_mean']
#         features['byte_q1'] = features['byte_mean']
#         features['byte_q3'] = features['byte_mean']
#         features['byte_iqr'] = 0.0
    
#     # Uniformity test (chi-squared) with safe calculation
#     try:
#         hist, _ = np.histogram(byte_array, bins=16, range=(0, 256))
#         expected = np.full(16, len(byte_array) / 16)
#         chi2_stat = np.sum((hist - expected) ** 2 / expected)
#         features['byte_chi2_uniform'] = float(chi2_stat)
#         features['byte_uniformity_pval'] = float(1 - stats.chi2.cdf(chi2_stat, 15))
#     except:
#         features['byte_chi2_uniform'] = 0.0
#         features['byte_uniformity_pval'] = 0.0
    
#     # Byte value distribution peaks
#     try:
#         unique_bytes = len(np.unique(byte_array))
#         features['byte_uniqueness_ratio'] = unique_bytes / len(byte_array)
#     except:
#         features['byte_uniqueness_ratio'] = 0.0
    
#     return features


def byte_statistical_features(hash_bytes):
    """Enhanced statistical analysis of byte values with robust error handling"""
    features = {}
    
    # FIX: Safe byte array conversion with proper error handling
    try:
        byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
    except (ValueError, TypeError):
        # Fallback: convert to list of byte values manually
        byte_array = np.array([b for b in hash_bytes], dtype=np.uint8)
    
    if len(byte_array) == 0:
        # Return default values for empty arrays
        features.update({
            'byte_mean': 0.0, 'byte_std': 0.0, 'byte_variance': 0.0,
            'byte_skewness': 0.0, 'byte_kurtosis': 0.0, 'byte_min': 0.0,
            'byte_max': 0.0, 'byte_range': 0.0, 'byte_median': 0.0,
            'byte_q1': 0.0, 'byte_q3': 0.0, 'byte_iqr': 0.0,
            'byte_chi2_uniform': 0.0, 'byte_uniformity_pval': 0.0,
            'byte_uniqueness_ratio': 0.0
        })
        return features
    
    # Basic statistical moments with safe calculations
    features['byte_mean'] = float(np.mean(byte_array))
    features['byte_std'] = float(np.std(byte_array)) if len(byte_array) > 1 else 0.0
    features['byte_variance'] = float(np.var(byte_array)) if len(byte_array) > 1 else 0.0
    
    # Higher-order moments (if enough data and variance)
    if len(byte_array) > 1 and features['byte_variance'] > 0:
        try:
            features['byte_skewness'] = float(stats.skew(byte_array))
            features['byte_kurtosis'] = float(stats.kurtosis(byte_array))
        except:
            features['byte_skewness'] = 0.0
            features['byte_kurtosis'] = 0.0
    else:
        features['byte_skewness'] = 0.0
        features['byte_kurtosis'] = 0.0
    
    # Range and distribution
    features['byte_min'] = float(np.min(byte_array))
    features['byte_max'] = float(np.max(byte_array))
    features['byte_range'] = features['byte_max'] - features['byte_min']
    
    # Percentile analysis with safe calculation
    try:
        features['byte_median'] = float(np.median(byte_array))
        features['byte_q1'] = float(np.percentile(byte_array, 25))
        features['byte_q3'] = float(np.percentile(byte_array, 75))
        features['byte_iqr'] = features['byte_q3'] - features['byte_q1']
    except:
        features['byte_median'] = features['byte_mean']
        features['byte_q1'] = features['byte_mean']
        features['byte_q3'] = features['byte_mean']
        features['byte_iqr'] = 0.0
    
    # Uniformity test (chi-squared) with safe calculation
    try:
        if len(byte_array) >= 16:  # Need enough samples for chi-square
            hist, _ = np.histogram(byte_array, bins=16, range=(0, 256))
            expected = np.full(16, len(byte_array) / 16)
            # Avoid division by zero in chi-square
            expected = np.where(expected == 0, 1e-10, expected)
            chi2_stat = np.sum((hist - expected) ** 2 / expected)
            features['byte_chi2_uniform'] = float(chi2_stat)
            features['byte_uniformity_pval'] = float(1 - stats.chi2.cdf(chi2_stat, 15))
        else:
            features['byte_chi2_uniform'] = 0.0
            features['byte_uniformity_pval'] = 0.0
    except:
        features['byte_chi2_uniform'] = 0.0
        features['byte_uniformity_pval'] = 0.0
    
    # Byte value distribution peaks
    try:
        unique_bytes = len(np.unique(byte_array))
        features['byte_uniqueness_ratio'] = unique_bytes / len(byte_array)
    except:
        features['byte_uniqueness_ratio'] = 0.0
    
    return features

def bit_distribution_features(hash_bytes):
    """Enhanced bit-level distribution analysis"""
    features = {}
    
    # Convert to bit array
    bit_array = []
    for byte in hash_bytes:
        bits = bin(byte)[2:].zfill(8)
        bit_array.extend([int(bit) for bit in bits])
    
    bit_array = np.array(bit_array)
    total_bits = len(bit_array)
    
    if total_bits == 0:
        return features
    
    # Bit statistics
    features['bit_mean'] = float(np.mean(bit_array))
    features['bit_ones_count'] = int(np.sum(bit_array))
    features['bit_zeros_count'] = total_bits - features['bit_ones_count']
    features['bit_balance'] = abs(features['bit_ones_count'] - features['bit_zeros_count']) / total_bits
    
    # Bit runs (consecutive identical bits)
    runs_ones = 0
    runs_zeros = 0
    current_run = 1
    all_runs_ones = []
    all_runs_zeros = []
    
    for i in range(1, total_bits):
        if bit_array[i] == bit_array[i-1]:
            current_run += 1
        else:
            if bit_array[i-1] == 1:
                runs_ones = max(runs_ones, current_run)
                all_runs_ones.append(current_run)
            else:
                runs_zeros = max(runs_zeros, current_run)
                all_runs_zeros.append(current_run)
            current_run = 1
    
    # Handle last run
    if bit_array[-1] == 1:
        runs_ones = max(runs_ones, current_run)
        all_runs_ones.append(current_run)
    else:
        runs_zeros = max(runs_zeros, current_run)
        all_runs_zeros.append(current_run)
    
    features['max_run_ones'] = runs_ones
    features['max_run_zeros'] = runs_zeros
    features['avg_run_ones'] = np.mean(all_runs_ones) if all_runs_ones else 0
    features['avg_run_zeros'] = np.mean(all_runs_zeros) if all_runs_zeros else 0
    
    # Bit transitions
    transitions = sum(1 for i in range(1, total_bits) if bit_array[i] != bit_array[i-1])
    features['bit_transition_ratio'] = transitions / (total_bits - 1) if total_bits > 1 else 0
    features['bit_transition_count'] = transitions
    
    # Monobit test (for randomness)
    features['monobit_test'] = abs(features['bit_ones_count'] - features['bit_zeros_count']) / math.sqrt(total_bits)
    
    # Positional bit analysis (first 32 positions)
    for i in range(min(32, total_bits)):
        features[f'bit_pos_{i}'] = int(bit_array[i]) if i < total_bits else 0
    
    return features

# def cryptographic_property_features(hash_bytes, hash_string):
#     """Enhanced cryptographic property tests and measurements"""
#     features = {}
    
#     # Compression test (random data shouldn't compress well)
#     try:
#         compressed_size = len(zlib.compress(hash_bytes))
#         features['compressibility'] = compressed_size / max(1, len(hash_bytes))
#         features['compression_ratio'] = compressed_size / len(hash_bytes)
#     except:
#         features['compressibility'] = 1.0
#         features['compression_ratio'] = 1.0
    
#     # Autocorrelation at different lags
#     byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
#     if len(byte_array) > 1:
#         try:
#             # Autocorrelation at multiple lags
#             for lag in [1, 2, 4, 8]:
#                 if len(byte_array) > lag:
#                     lag_corr = np.corrcoef(byte_array[:-lag], byte_array[lag:])[0,1]
#                     features[f'autocorrelation_lag{lag}'] = float(0.0 if np.isnan(lag_corr) else lag_corr)
#                 else:
#                     features[f'autocorrelation_lag{lag}'] = 0.0
#         except:
#             for lag in [1, 2, 4, 8]:
#                 features[f'autocorrelation_lag{lag}'] = 0.0
#     else:
#         for lag in [1, 2, 4, 8]:
#             features[f'autocorrelation_lag{lag}'] = 0.0
    
#     # Block-based analysis for common hash sizes
#     block_sizes = [4, 8, 16, 32, 64]
#     for block_size in block_sizes:
#         if len(hash_bytes) >= block_size:
#             block = hash_bytes[:block_size]
#             block_array = np.frombuffer(block, dtype=np.uint8)
#             features[f'block_{block_size}_mean'] = float(np.mean(block_array))
#             features[f'block_{block_size}_std'] = float(np.std(block_array))
#             features[f'block_{block_size}_entropy'] = calculate_byte_entropy(block)
    
#     # Entropy of byte distribution
#     if len(hash_bytes) > 0:
#         byte_entropy = calculate_byte_entropy(hash_bytes)
#         features['byte_entropy'] = byte_entropy
#         features['byte_entropy_ratio'] = byte_entropy / 8.0  # Normalized to max entropy
    
#     # Avalanche effect simulation (bit flip analysis)
#     if len(hash_bytes) > 1:
#         features.update(avalanche_analysis(hash_bytes))
    
#     return features

def cryptographic_property_features(hash_bytes, hash_string):
    """Enhanced cryptographic property tests with robust error handling"""
    features = {}
    
    # FIX: Safe byte array conversion
    try:
        byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
    except (ValueError, TypeError):
        byte_array = np.array([b for b in hash_bytes], dtype=np.uint8)
    
    if len(byte_array) == 0:
        return features
    
    # Compression test (random data shouldn't compress well)
    try:
        compressed_size = len(zlib.compress(hash_bytes))
        features['compressibility'] = compressed_size / max(1, len(hash_bytes))
        features['compression_ratio'] = compressed_size / len(hash_bytes)
    except:
        features['compressibility'] = 1.0
        features['compression_ratio'] = 1.0
    
    # Autocorrelation at different lags with robust handling
    if len(byte_array) > 1:
        try:
            # Autocorrelation at multiple lags
            for lag in [1, 2, 4, 8]:
                if len(byte_array) > lag:
                    # Use safer correlation calculation
                    x1 = byte_array[:-lag]
                    x2 = byte_array[lag:]
                    
                    # Check if we have enough variance
                    if np.std(x1) > 0 and np.std(x2) > 0:
                        correlation_matrix = np.corrcoef(x1, x2)
                        if correlation_matrix.shape == (2, 2):
                            lag_corr = correlation_matrix[0, 1]
                            features[f'autocorrelation_lag{lag}'] = float(0.0 if np.isnan(lag_corr) else lag_corr)
                        else:
                            features[f'autocorrelation_lag{lag}'] = 0.0
                    else:
                        features[f'autocorrelation_lag{lag}'] = 0.0
                else:
                    features[f'autocorrelation_lag{lag}'] = 0.0
        except:
            for lag in [1, 2, 4, 8]:
                features[f'autocorrelation_lag{lag}'] = 0.0
    else:
        for lag in [1, 2, 4, 8]:
            features[f'autocorrelation_lag{lag}'] = 0.0
    # Block-based analysis for common hash sizes
    block_sizes = [4, 8, 16, 32, 64]
    for block_size in block_sizes:
        if len(hash_bytes) >= block_size:
            block = hash_bytes[:block_size]
            block_array = np.frombuffer(block, dtype=np.uint8)
            features[f'block_{block_size}_mean'] = float(np.mean(block_array))
            features[f'block_{block_size}_std'] = float(np.std(block_array)) if len(block_array) > 1 else 0.0
            features[f'block_{block_size}_entropy'] = calculate_byte_entropy(block)
    
    # Entropy of byte distribution
    if len(hash_bytes) > 0:
        byte_entropy = calculate_byte_entropy(hash_bytes)
        features['byte_entropy'] = byte_entropy
        features['byte_entropy_ratio'] = byte_entropy / 8.0  # Normalized to max entropy
    
    # Avalanche effect simulation (bit flip analysis)
    if len(hash_bytes) > 1:
        features.update(avalanche_analysis(hash_bytes))
    
    return features

def calculate_byte_entropy(byte_data):
    """Calculate Shannon entropy of byte data"""
    if len(byte_data) == 0:
        return 0.0
    
    byte_counts = Counter(byte_data)
    entropy = 0.0
    total_bytes = len(byte_data)
    
    for count in byte_counts.values():
        p = count / total_bytes
        entropy -= p * math.log2(p)
    
    return entropy

def avalanche_analysis(hash_bytes):
    """Analyze avalanche effect by flipping bits"""
    features = {}
    
    if len(hash_bytes) < 2:
        return features
    
    # FIX: Safe byte array conversion
    try:
        byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
    except (ValueError, TypeError):
        byte_array = np.array([b for b in hash_bytes], dtype=np.uint8)
    
    if len(byte_array) < 2:
        return features
    
    # Flip each bit position and measure hamming distance
    total_bits = len(byte_array) * 8
    hamming_distances = []
    
    # Test first few bit flips for performance
    test_bits = min(16, total_bits)
    for bit_pos in range(test_bits):
        try:
            # Create modified byte array with one bit flipped
            modified_bytes = byte_array.copy()
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            
            if byte_idx < len(modified_bytes):
                # Flip the bit
                modified_bytes[byte_idx] ^= (1 << (7 - bit_idx))
                
                # Calculate hamming distance
                original_bits = np.unpackbits(byte_array)
                modified_bits = np.unpackbits(modified_bytes)
                hamming_dist = np.sum(original_bits != modified_bits)
                hamming_distances.append(hamming_dist)
        except:
            continue
    
    if hamming_distances:
        features['avalanche_mean'] = float(np.mean(hamming_distances))
        features['avalanche_std'] = float(np.std(hamming_distances))
        features['avalanche_min'] = float(np.min(hamming_distances))
        features['avalanche_max'] = float(np.max(hamming_distances))
    
    return features

def encoding_format_features(hash_string, hash_bytes):
    """Enhanced encoding format detection and structural patterns"""
    features = {}
    
    # Base64 patterns
    features['is_likely_base64'] = bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', hash_string))
    features['base64_padding_count'] = hash_string.count('=')
    features['has_base64_plus'] = '+' in hash_string
    features['has_base64_slash'] = '/' in hash_string
    
    # Base64 URL-safe patterns
    features['is_likely_base64url'] = bool(re.match(r'^[A-Za-z0-9_-]*$', hash_string))
    features['has_base64url_dash'] = '-' in hash_string
    features['has_base64url_underscore'] = '_' in hash_string
    
    # Hex encoding quality
    features['is_valid_hex'] = bool(re.match(r'^[a-fA-F0-9]+$', hash_string))
    features['hex_length_even'] = int(len(hash_string) % 2 == 0) if features['is_valid_hex'] else 0
    features['hex_odd_padding_needed'] = int(len(hash_string) % 2 != 0) if features['is_valid_hex'] else 0
    
    # Special pattern indicators
    features['starts_with_dollar'] = int(hash_string.startswith('$'))
    features['ends_with_equals'] = int(hash_string.endswith('='))
    features['has_double_dollar'] = int('$$' in hash_string)
    features['has_colon_separators'] = int(hash_string.count(':') >= 2)
    features['has_dot_separators'] = int(hash_string.count('.') >= 2)
    features['has_dash_separators'] = int(hash_string.count('-') >= 2)
    features['has_underscore_separators'] = int(hash_string.count('_') >= 2)
    features['has_comma_separators'] = int(hash_string.count(',') >= 2)  # For Argon2 parameters
    
    # Unix crypt format patterns
    dollar_parts = hash_string.split('$')
    features['dollar_sections'] = len(dollar_parts) - 1
    if features['dollar_sections'] >= 2:
        features['crypt_id'] = len(dollar_parts[1]) if dollar_parts[1] else 0
        # MCF algorithm ID patterns
        features['mcf_id_is_numeric'] = int(dollar_parts[1].isdigit()) if dollar_parts[1] else 0
        features['mcf_id_is_alpha'] = int(dollar_parts[1].isalpha()) if dollar_parts[1] else 0
        features['mcf_id_is_alphanum'] = int(dollar_parts[1].isalnum()) if dollar_parts[1] else 0
    else:
        features['crypt_id'] = 0
        features['mcf_id_is_numeric'] = 0
        features['mcf_id_is_alpha'] = 0
        features['mcf_id_is_alphanum'] = 0
    
    # JWT-like patterns
    dot_parts = hash_string.split('.')
    features['dot_sections'] = len(dot_parts) - 1
    
    return features


def algorithm_specific_features(hash_string, hash_bytes, length):
    """Enhanced algorithm-specific pattern detection"""
    features = {}
    hash_lower = hash_string.lower()
    
    # Length-based patterns for common hashes
    common_lengths = {16, 32, 40, 56, 64, 80, 96, 128}
    features['is_common_hash_length'] = int(length in common_lengths)
    features['exact_length'] = length
    
    # Specific algorithm patterns with enhanced detection
    features['has_argon_pattern'] = int('argon2' in hash_lower or 'argon2id' in hash_lower or 'argon2i' in hash_lower)
    features['has_pbkdf2_pattern'] = int('pbkdf2' in hash_lower or any(hash_string.startswith(prefix) for prefix in ['$pbkdf2$', '$pbkdf2-sha256$']))
    features['has_bcrypt_pattern'] = int(hash_string.startswith(('$2a$', '$2b$', '$2y$', '$2x$')))
    features['has_scrypt_pattern'] = int('scrypt' in hash_lower or hash_string.startswith('$scrypt$'))
    
    # Enhanced SHA family patterns
    features['has_sha_pattern'] = int('sha' in hash_lower)
    features['has_md5_pattern'] = int(length == 32 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_sha1_pattern'] = int(length == 40 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_sha224_pattern'] = int(length == 56 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_sha256_pattern'] = int(length == 64 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_sha384_pattern'] = int(length == 96 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_sha512_pattern'] = int(length == 128 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    
    # Windows hashes
    features['has_ntlm_pattern'] = int(length == 32 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_lm_hash_pattern'] = int(length == 32 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    
    # Database hashes
    features['has_mysql_pattern'] = int(length == 16 and bool(re.match(r'^[a-fA-F0-9]+$', hash_string)))
    features['has_mysql41_pattern'] = int(length == 40 and bool(re.match(r'^[a-fA-F0-9]*$', hash_string)))
    features['has_postgres_pattern'] = int(hash_string.startswith('md5') and length == 35)
    
    # JWT token pattern
    features['has_jwt_pattern'] = int(len(hash_string.split('.')) == 3 and all(len(part) > 10 for part in hash_string.split('.')))
    
    # Crypt format variants
    features['has_unix_crypt_pattern'] = int(hash_string.startswith('$') and features.get('dollar_sections', 0) >= 3)
    features['has_md5_crypt_pattern'] = int(hash_string.startswith('$1$'))
    features['has_sha256_crypt_pattern'] = int(hash_string.startswith('$5$'))
    features['has_sha512_crypt_pattern'] = int(hash_string.startswith('$6$'))
    
    # Enhanced likelihood scores
    features['likely_md5'] = features['has_md5_pattern']
    features['likely_sha1'] = features['has_sha1_pattern']
    features['likely_sha256'] = features['has_sha256_pattern']
    features['likely_sha512'] = features['has_sha512_pattern']
    features['likely_bcrypt'] = features['has_bcrypt_pattern']
    
    return features

def advanced_crypto_analysis(hash_bytes, hash_string):
    """Advanced cryptographic analysis including encoding-specific distributions"""
    features = {}
    
    # FIX: Safe byte array conversion
    try:
        byte_array = np.frombuffer(hash_bytes, dtype=np.uint8)
    except (ValueError, TypeError):
        byte_array = np.array([b for b in hash_bytes], dtype=np.uint8)
    
    if len(byte_array) == 0:
        return features
    
    # Byte value clustering analysis
    try:
        byte_diff = np.diff(byte_array)
        features['byte_diff_mean'] = float(np.mean(np.abs(byte_diff))) if len(byte_diff) > 0 else 0
        features['byte_diff_std'] = float(np.std(byte_diff)) if len(byte_diff) > 0 else 0
    except:
        features['byte_diff_mean'] = 0.0
        features['byte_diff_std'] = 0.0
    
    # Check for ASCII printable range concentration
    try:
        ascii_printable = np.sum((byte_array >= 32) & (byte_array <= 126))
        features['ascii_printable_ratio'] = ascii_printable / len(byte_array)
    except:
        features['ascii_printable_ratio'] = 0.0
    
    # Check for null bytes (common in some formats)
    try:
        features['null_byte_count'] = int(np.sum(byte_array == 0))
        features['null_byte_ratio'] = features['null_byte_count'] / len(byte_array)
    except:
        features['null_byte_count'] = 0
        features['null_byte_ratio'] = 0.0
    
    # High byte values (often indicate binary data)
    try:
        features['high_byte_count'] = int(np.sum(byte_array > 127))
        features['high_byte_ratio'] = features['high_byte_count'] / len(byte_array)
    except:
        features['high_byte_count'] = 0
        features['high_byte_ratio'] = 0.0
    
    # Byte value mode analysis
    if len(byte_array) > 0:
        try:
            mode_result = stats.mode(byte_array)
            features['byte_mode_value'] = float(mode_result.mode[0])
            features['byte_mode_frequency'] = float(mode_result.count[0] / len(byte_array))
        except:
            features['byte_mode_value'] = 0.0
            features['byte_mode_frequency'] = 0.0
    
    # Run length encoding complexity
    try:
        features['rle_complexity'] = calculate_rle_complexity(byte_array)
    except:
        features['rle_complexity'] = 0.0
    
    return features

def calculate_rle_complexity(byte_array):
    """Calculate Run-Length Encoding complexity"""
    if len(byte_array) == 0:
        return 0
    
    runs = 1
    for i in range(1, len(byte_array)):
        if byte_array[i] != byte_array[i-1]:
            runs += 1
    
    return runs / len(byte_array)

def get_feature_names():
    """Return the complete list of feature names"""
    base_features = [
        'length', 'is_hex', 'has_symbols', 'is_alphanumeric', 'is_printable',
        'digit_count', 'letter_count', 'uppercase_count', 'lowercase_count', 
        'symbol_count', 'hex_lower_count', 'hex_upper_count', 'space_count',
        'digit_ratio', 'letter_ratio', 'uppercase_ratio', 'lowercase_ratio', 
        'symbol_ratio', 'hex_ratio', 'space_ratio', 'char_entropy', 
        'unique_chars', 'char_unique_ratio', 'most_common_char_freq',
        'consecutive_repeated_chars', 'char_transitions', 'detected_encoding'
    ]

    mcf_features = [
        'is_mcf_hash', 'mcf_parts_count', 'mcf_has_parameters', 'mcf_has_salt',
        'mcf_salt_length', 'mcf_hash_component_length', 'mcf_algorithm_id_length',
        'is_bcrypt', 'is_argon2', 'is_argon2id', 'is_argon2i', 'is_argon2d',
        'is_md5_crypt', 'is_sha256_crypt', 'is_sha512_crypt', 'is_scrypt', 
        'is_yescrypt', 'is_cisco_type8', 'is_cisco_type9', 'is_pbkdf2',
        'bcrypt_cost_factor', 'argon2_memory', 'argon2_iterations', 
        'argon2_parallelism', 'argon2_version',
        'mcf_salt_is_hex', 'mcf_salt_is_b64', 'mcf_hash_is_hex', 'mcf_hash_is_b64',
        'mcf_id_is_numeric', 'mcf_id_is_alpha', 'mcf_id_is_alphanum'
    ]
    
    statistical_features = [
        'byte_mean', 'byte_std', 'byte_variance', 'byte_skewness', 'byte_kurtosis',
        'byte_min', 'byte_max', 'byte_range', 'byte_median', 'byte_q1', 'byte_q3',
        'byte_iqr', 'byte_chi2_uniform', 'byte_uniformity_pval', 'byte_uniqueness_ratio'
    ]
    

    bit_features = [
        'bit_mean', 'bit_ones_count', 'bit_zeros_count', 'bit_balance',
        'max_run_ones', 'max_run_zeros', 'avg_run_ones', 'avg_run_zeros',
        'bit_transition_ratio', 'bit_transition_count', 'monobit_test'
    ]
    
    # Add positional bit features
    bit_features.extend([f'bit_pos_{i}' for i in range(32)])
    
    crypto_features = [
        'compressibility', 'compression_ratio', 'byte_entropy', 'byte_entropy_ratio'
    ]
    
    # Add autocorrelation features
    crypto_features.extend([f'autocorrelation_lag{lag}' for lag in [1, 2, 4, 8]])
    
    # Add block analysis features
    block_sizes = [4, 8, 16, 32, 64]
    for size in block_sizes:
        crypto_features.extend([f'block_{size}_mean', f'block_{size}_std', f'block_{size}_entropy'])
    
    # Add avalanche features
    crypto_features.extend(['avalanche_mean', 'avalanche_std', 'avalanche_min', 'avalanche_max'])
    
    encoding_features = [
        'is_likely_base64', 'base64_padding_count', 'has_base64_plus', 'has_base64_slash',
        'is_likely_base64url', 'has_base64url_dash', 'has_base64url_underscore',
        'is_valid_hex', 'hex_length_even', 'hex_odd_padding_needed', 'starts_with_dollar', 
        'ends_with_equals', 'has_double_dollar', 'has_colon_separators', 'has_dot_separators',
        'has_dash_separators', 'has_underscore_separators', 'dollar_sections', 'crypt_id',
        'dot_sections'
    ]
    
    algorithm_features = [
        'is_common_hash_length', 'exact_length', 'has_argon_pattern', 'has_pbkdf2_pattern', 
        'has_bcrypt_pattern', 'has_scrypt_pattern', 'has_sha_pattern', 'has_md5_pattern',
        'has_sha1_pattern', 'has_sha224_pattern', 'has_sha256_pattern', 'has_sha384_pattern',
        'has_sha512_pattern', 'has_ntlm_pattern', 'has_lm_hash_pattern', 'has_mysql_pattern',
        'has_mysql41_pattern', 'has_postgres_pattern', 'has_jwt_pattern', 'has_unix_crypt_pattern',
        'has_md5_crypt_pattern', 'has_sha256_crypt_pattern', 'has_sha512_crypt_pattern',
        'likely_md5', 'likely_sha1', 'likely_sha256', 'likely_sha512', 'likely_bcrypt'
    ]
    
    advanced_features = [
        'byte_diff_mean', 'byte_diff_std', 'ascii_printable_ratio', 'null_byte_count',
        'null_byte_ratio', 'high_byte_count', 'high_byte_ratio', 'byte_mode_value',
        'byte_mode_frequency', 'rle_complexity'
    ]
    
    return (base_features + mcf_features + statistical_features + bit_features + 
            crypto_features + encoding_features + algorithm_features + advanced_features)

# Example usage and testing
if __name__ == "__main__":
    test_hashes = [
        "5d41402abc4b2a76b9719d911017c592",  # MD5
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA1
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # SHA256
        "$2a$10$N9qo8uLOickgx2ZMRZoMye",  # Bcrypt
        "abc123",  # Odd-length hex
        "dGVzdA==",  # Base64
    ]
    
    for hash_val in test_hashes:
        print(f"\nAnalyzing: {hash_val}")
        features = advanced_hash_features(hash_val)
        print(f"Total features extracted: {len(features)}")
        print(f"Detected encoding: {features.get('detected_encoding', 'unknown')}")
        print("Key features:")
        for key, value in list(features.items())[:15]:
            print(f"  {key}: {value}")
