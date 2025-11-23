import re
from sys import argv
import zlib
from hashlib import md5
from Crypto.Hash import MD4 
import base64
import argparse
import joblib
import numpy as np
from hash_features import advanced_hash_features
# from GUI.main import launch_gui
import os
import sys
os.system("")   # Enable ANSI colors on Windows



# ======================= COLORS ==========================
# Original Neon Blue Gradient
C1 = "\033[38;5;51m"      # Neon Cyan
C2 = "\033[38;5;87m"      # Aqua Glow
C3 = "\033[38;5;123m"     # Teal
C4 = "\033[38;5;159m"     # Light Neon
C5 = "\033[38;5;195m"     # White-Blue Glow

RESET = "\033[0m"

# ======================= AWESOME NESTED GRADIENT PACK ==========================

GRADIENTS = {
    "PURPLE_GLOW": {
        "P1": "\033[38;5;93m",     # Purple
        "P2": "\033[38;5;129m",    # Soft Violet
        "P3": "\033[38;5;165m",    # Magenta Glow
        "P4": "\033[38;5;201m",    # Pink Neon
        "P5": "\033[38;5;207m",    # Hot Pink-White Glow
    },

    "ORANGE_SUNSET": {
        "O1": "\033[38;5;202m",    # Vibrant Orange
        "O2": "\033[38;5;208m",    # Sunset Orange
        "O3": "\033[38;5;214m",    # Golden Orange
        "O4": "\033[38;5;220m",    # Yellow-Gold Glow
        "O5": "\033[38;5;226m",    # Neon Yellow
    },

    "RED_LASER": {
        "R1": "\033[38;5;196m",    # Laser Red
        "R2": "\033[38;5;199m",    # Red-Pink
        "R3": "\033[38;5;201m",    # Hot Pink
        "R4": "\033[38;5;206m",    # Magenta Glow
        "R5": "\033[38;5;213m",    # Light Magenta-White
    },

    "GALAXY": {
        "G1": "\033[38;5;63m",     # Deep Blue
        "G2": "\033[38;5;99m",     # Indigo
        "G3": "\033[38;5;135m",    # Purple-Blue Mix
        "G4": "\033[38;5;171m",    # Neon Purple
        "G5": "\033[38;5;207m",    # Pink Neon Glow
    },

    "CYBER_SUNSET": {
        "S1": "\033[38;5;91m",     # Pinkish Purple
        "S2": "\033[38;5;127m",    # Purple-Red
        "S3": "\033[38;5;161m",    # Magenta-Red
        "S4": "\033[38;5;197m",    # Hot Red
        "S5": "\033[38;5;214m",    # Orange Glow
    }
} 
# ======================= LOGO USING ALL GRADIENTS ============================
P = GRADIENTS["PURPLE_GLOW"]
O = GRADIENTS["ORANGE_SUNSET"]
R = GRADIENTS["RED_LASER"]
G = GRADIENTS["GALAXY"]
S = GRADIENTS["CYBER_SUNSET"]

version = " 2.0.0"

logo = f"""
{P['P1']}       __      _,   __, __    _______ __     _,    ,___ ______{RESET}
{O['O2']}      ( /  /  / |  (   ( /  /(  /  ( /  )   / |   /   /(  /   {RESET}
{R['R3']}       /--/  /--|   `.  /--/   /    /--<   /--|  /       /--  {RESET}
{G['G4']}      /  /__/   |_(___)/  /_ _/    /   \\__/   |_(___/  (/____/ 🔐{RESET}
{S['S5']}     ______                                      version=>{version}{RESET}
{S['S2']}                                                 ________________{RESET}
"""



# # Your original logo and version - KEEP EXACTLY THE SAME

# logo = f"""
#        __      _,   __, __    _______ __     _,    ,___ ______
#       ( /  /  / |  (   ( /  /(  /  ( /  )   / |   /   /(  /   
#        /--/  /--|   `.  /--/   /    /--<   /--|  /       /--  
#       /  /__/   |_(___)/  /_ _/    /   \__/   |_(___/  (/____/
#      ______                                            version=>{version}      

# """

supported_hashes = [
    "MD5", "MD4", "SHA-1", "SHA-256", "SHA-512",
    "CRC32", "CRC32b", "CRC32b-PHP", "NTLM",
    "CRC32_padded", "SHA-224", "SHA-384",
    "SHA3-256", "SHA3-512", "Blake2b",
    "RIPEMD-160", "Whirlpool", "Adler-32",
    "FCS-32", "GHash-32-3", "GHash-32-5",
    "FNV-132", "Fletcher-32", "Joaat",
    "ELF-32", "XOR-32", "Microsoft Outlook PST",
    "Dahua", "bcrypt", "PBKDF2",
    "Argon2i", "Argon2d", "Argon2id",
    "pbkdf2-sha256_django", "pbkdf2-sha1_django",
    "pbkdf2-sha512_django",
    "pbkdf2-sha256(salted, hex_format)",
    "pbkdf2-sha512(salted, hex_format)",
    "pbkdf2-sha1(salted, hex_format)",
    "ML Enhanced(56+ AI-Predicted Types)"
]

# # NEW: ML Model Stats Display Function
def get_ml_model_stats():
    """Load and display ML model training statistics"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        models_dir = os.path.join(project_root, "Models")
        model_path = os.path.join(models_dir, "hashtrace_ml_advanced.pkl")
        
        if os.path.exists(model_path):
            model_data = joblib.load(model_path)
            
            stats = {
                'model_name': model_data.get('model_name', 'Unknown'),
                'version': model_data.get('version', '1.0.0'),
                'timestamp': model_data.get('timestamp', 'Unknown'),
                'test_accuracy': model_data.get('performance', {}).get('test_accuracy', 0),
                'f1_score': model_data.get('performance', {}).get('f1_score', 0),
                'training_time': model_data.get('performance', {}).get('training_time', 0),
                'feature_count': len(model_data.get('feature_names', [])),
                'class_count': len(model_data.get('classes', [])),
                'all_models_results': model_data.get('all_models_results', {})
            }
            return stats
        else:
            return None
    except Exception as e:
        print(f"⚠️  Could not load ML model stats: {e}")
        return None

# def display_ml_stats_banner():
#     """Display ML model statistics in a formatted banner"""
#     stats = get_ml_model_stats()
    
#     if not stats:
#         ml_banner = """
# 🤖 AI MODEL STATUS: NOT TRAINED
# ------------------------------------------------------------------------------------------------
#    📊 No trained ML model found. Train a model first for AI-powered hash identification.
#    💡 Run: python train_model.py to train the AI model
# ------------------------------------------------------------------------------------------------
# """
#         return ml_banner
    
#     # Format the timestamp
#     try:
#         from datetime import datetime
#         timestamp = datetime.fromisoformat(stats['timestamp'].replace('Z', '+00:00'))
#         formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     except:
#         formatted_time = stats['timestamp']
    
#     # Get all model results for comparison
#     all_models = stats.get('all_models_results', {})
    
#     ml_banner = f"""
# 🤖 AI MODEL STATUS: ACTIVE & TRAINED
# ------------------------------------------------------------------------------------------------
#    🏆 BEST MODEL: {stats['model_name']:<16} 📈 ACCURACY: {stats['test_accuracy']:.2%}
#    ⚡ F1-SCORE: {stats['f1_score']:.4f}          ⏱️  TRAIN TIME: {stats['training_time']:.1f}s
#    🔧 FEATURES: {stats['feature_count']:<3}        🎯 CLASSES: {stats['class_count']:<3}
#    📅 TRAINED: {formatted_time}
# """
    
#     # Add model comparison if available
#     if all_models:
#         ml_banner += "   \n   📊 MODEL COMPARISON:\n"
#         for model_name, result in all_models.items():
#             if 'test_accuracy' in result:
#                 ml_banner += f"      • {model_name:<18}: {result['test_accuracy']:.2%}\n"
    
#     ml_banner += "------------------------------------------------------------------------------------------------"
    
#     return ml_banner




# def make_bar(value, length=25, color="\033[96m"):
#     """Generate a colored progress bar [███░░░] style"""
#     filled = int(value * length)
#     empty = length - filled
#     return f"{color}[{'█' * filled}{'░' * empty}]{RESET} {value*100:.0f}%"


# def display_ml_stats_banner():
#     """Display ML model statistics inside a table with visualization bars"""
#     stats = get_ml_model_stats()
    
#     if not stats:
#         return """
# 🤖 AI MODEL STATUS: NOT TRAINED
# ---------------------------------------------------------------------------------------
#    📊 No trained ML model found. Train a model first for AI-powered hash identification.
#    💡 Run: python train_model.py to train the AI model
# ---------------------------------------------------------------------------------------
# """

#     # Formatting timestamp
#     try:
#         from datetime import datetime
#         timestamp = datetime.fromisoformat(stats['timestamp'].replace('Z', '+00:00'))
#         formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     except:
#         formatted_time = stats['timestamp']
    
#     # Colors
#     C1 = "\033[95m"   # Purple
#     C2 = "\033[96m"   # Cyan
#     C3 = "\033[94m"   # Blue
#     C4 = "\033[92m"   # Green
#     RESET = "\033[0m"

#     # Create visual bars
#     acc_bar = make_bar(stats['test_accuracy'], color=C2)
#     f1_bar = make_bar(stats['f1_score'], color=C3)

#     LEFT_COL_WIDTH = 15
#     RIGHT_COL_WIDTH = 55

#     # Table border (73 total = 15 + 3 + 55)
#     line = f"{C1}+{'-' * (LEFT_COL_WIDTH + 2)}{C1}+{'-' * (RIGHT_COL_WIDTH + 2)}{C1}+{RESET}"

#     table = f"""
#     🤖 {C4}AI MODEL STATUS: ACTIVE & TRAINED{RESET}
#     {line}
#     | {C2}{'Model Name':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {stats['model_name']:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     | {C2}{'Version':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {stats['version']:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     | {C2}{'Trained On':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {formatted_time:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     {line}
#     | {C3}{'Accuracy':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {acc_bar:<{RIGHT_COL_WIDTH}} {C1}         |{RESET}
#     | {C3}{'F1 Score':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {f1_bar:<{RIGHT_COL_WIDTH}} {C1}         |{RESET}
#     | {C3}{'Train Time':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['training_time'])[:RIGHT_COL_WIDTH] + ' sec':<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     | {C3}{'Features':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['feature_count']):<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     | {C3}{'Classes':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['class_count']):<{RIGHT_COL_WIDTH}} {C1}|{RESET}
#     {line}
#     """


#     # Model comparison section (optional)
#     all_models = stats.get("all_models_results", {})
#     if all_models:
#         table += f"\n{C4}📊 MODEL COMPARISON:{RESET}\n"
#         for model_name, result in all_models.items():
#             if "test_accuracy" in result:
#                 bar = make_bar(result["test_accuracy"], color=C4)
#                 table += f"   • {model_name:<16}: {bar}\n"

#     table += line
#     return table



def make_bar(value, length=25, color="\033[96m"):
    """Generate a colored progress bar [███░░░] style with exact percentage"""
    filled = int(value * length)
    empty = length - filled
    return f"{color}[{'█' * filled}{'░' * empty}]{RESET} {value*100:.1f}%"

def calculate_model_score(result):
    """Calculate total score as sum of accuracy_score + f1_score + cv_score + time_score"""
    total_score = 0.0
    
    # Add accuracy score
    if 'test_accuracy' in result:
        total_score += result['test_accuracy']
    
    # Add F1 score
    if 'f1_score' in result:
        total_score += result['f1_score']
    
    # Add cross-validation score
    if 'cv_score' in result:
        total_score += result['cv_score']
    
    # Add time score (inverse - lower time is better)
    if 'training_time' in result and result['training_time'] > 0:
        # Calculate time score as 1/(1+time) so lower times get higher scores
        time_score = 1.0 / (1.0 + result['training_time'])
        total_score += time_score
    
    return total_score


def display_ml_stats_banner():
    """Display ML model statistics inside a table with visualization bars"""
    stats = get_ml_model_stats()
    
    if not stats:
        return """
🤖 AI MODEL STATUS: NOT TRAINED
---------------------------------------------------------------------------------------
   📊 No trained ML model found. Train a model first for AI-powered hash identification.
   💡 Run: python train_model.py to train the AI model
---------------------------------------------------------------------------------------
"""

    # Formatting timestamp
    try:
        from datetime import datetime
        timestamp = datetime.fromisoformat(stats['timestamp'].replace('Z', '+00:00'))
        formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    except:
        formatted_time = stats['timestamp']
    
    # Colors
    C1 = "\033[95m"   # Purple
    C2 = "\033[96m"   # Cyan
    C3 = "\033[94m"   # Blue
    C4 = "\033[92m"   # Green
    C5 = "\033[93m"   # Yellow
    RESET = "\033[0m"

    # Create visual bars with exact decimal values
    acc_bar = make_bar(stats['test_accuracy'], color=C2)
    f1_bar = make_bar(stats['f1_score'], color=C3)

    LEFT_COL_WIDTH = 15
    RIGHT_COL_WIDTH = 55

    # Table border (73 total = 15 + 3 + 55)
    line = f"{C1}+{'-' * (LEFT_COL_WIDTH + 2)}{C1}+{'-' * (RIGHT_COL_WIDTH + 2)}{C1}+{RESET}"

    table = f"""
🤖 {C4}AI MODEL STATUS: ACTIVE & TRAINED{RESET}
{line}
| {C2}{'Model Name':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {stats['model_name']:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
| {C2}{'Version':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {stats['version']:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
| {C2}{'Trained On':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {formatted_time:<{RIGHT_COL_WIDTH}} {C1}|{RESET}
{line}
| {C3}{'Accuracy':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {acc_bar:<{RIGHT_COL_WIDTH}} {C1}         |{RESET}
| {C3}{'F1 Score':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {f1_bar:<{RIGHT_COL_WIDTH}} {C1}         |{RESET}
| {C3}{'Train Time':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['training_time'])[:RIGHT_COL_WIDTH] + ' sec':<{RIGHT_COL_WIDTH}} {C1}|{RESET}
| {C3}{'Features':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['feature_count']):<{RIGHT_COL_WIDTH}} {C1}|{RESET}
| {C3}{'Classes':<{LEFT_COL_WIDTH}}{RESET} {C1}|{RESET} {str(stats['class_count']):<{RIGHT_COL_WIDTH}} {C1}|{RESET}
{line}
"""

    # Model comparison section - formatted as table
    all_models = stats.get("all_models_results", {})
    if all_models:
        # Define column widths
        model_width = 18
        metric_width = 9
        time_width = 8
        score_width = 8
        
        # Header
        header_line = f"{C1}{'-' * (model_width + metric_width*4 + time_width + score_width + 13)}{RESET}"
        
        model_comp = f"\n{C4}📊 Model Comparison:{RESET}\n"
        model_comp += f"{C5}{'Model':<{model_width}} | {'Test Acc':<{metric_width}} | {'F1 Score':<{metric_width}} | {'CV Score':<{metric_width}} | {'Time(s)':<{time_width}} | {'Score':<{score_width}}{RESET}\n"
        model_comp += header_line + "\n"
        
        # Add each model's data
        for model_name, result in all_models.items():
            test_acc = f"{result.get('test_accuracy', 0):.4f}" if 'test_accuracy' in result else "N/A"
            f1_score = f"{result.get('f1_score', 0):.4f}" if 'f1_score' in result else "N/A"
            cv_score = f"{result.get('cv_score', 0):.4f}" if 'cv_score' in result else "N/A"
            train_time = f"{result.get('training_time', 0):.2f}" if 'training_time' in result else "N/A"
            
            # Calculate score as sum of all metrics
            calculated_score = calculate_model_score(result)
            final_score = f"{calculated_score:.4f}"
            
            model_comp += f"{model_name:<{model_width}} | {C2}{test_acc:<{metric_width}}{RESET} | {C3}{f1_score:<{metric_width}}{RESET} | {C4}{cv_score:<{metric_width}}{RESET} | {C5}{train_time:<{time_width}}{RESET} | {C1}{final_score:<{score_width}}{RESET}\n"
        
        model_comp += header_line
        table += model_comp

    return table



# Your original algorithms dictionary - KEEP EXACTLY THE SAME
algorithms = {
    "106020": "MD5",
    "106030": "MD4",
    "106040": "SHA-1",
    "106060": "SHA-256",
    "106080": "SHA-512",
    "106100": "CRC32",
    "106102": "CRC32b",
    "106103": "CRC32b-PHP",
    "106120": "NTLM",
    "106101": "CRC32_padded",
    "106140": "SHA-224",
    "106160": "SHA-384",
    "106180": "SHA3-256",
    "106200": "SHA3-512",
    "106220": "Blake2b",
    "106240": "RIPEMD-160",
    "106260": "Whirlpool",
    "106104": "Adler-32",
    "106105": "FCS-32",
    "106106": "GHash-32-3",
    "106107": "GHash-32-5",
    "106108": "FNV-132",
    "106109": "Fletcher-32",
    "106110": "Joaat",
    "106111": "ELF-32",
    "106112": "XOR-32",
    "106113": "Microsoft Outlook PST",
    "106114": "Dahua",
    "bcrypt (salted)": "bcrypt",
    "PBKDF2 (salted)": "PBKDF2",
    "Argon2i(salted)": "Argon2i",
    "Argon2d(salted)": "Argon2d",
    "Argon2id(salted)": "Argon2id",
    "pbkdf2-sha256 (salted)": "pbkdf2-sha256_django",
    "pbkdf2-sha1 (salted)": "pbkdf2-sha1_django",
    "pbkdf2-sha512 (salted)": "pbkdf2-sha512_django",
    "pbkdf2-sha256 (salted, hex format)": "pbkdf2-sha256(salted ,hex_format)",
    "pbkdf2-sha512 (salted, hex format)": "pbkdf2-sha512 (salted, hex format)",
    "pbkdf2-sha1 (salted, hex format)": "pbkdf2-sha1 (salted, hex format)"
}

# YOUR ORIGINAL HASH DETECTION FUNCTIONS - KEEP ALL OF THEM EXACTLY THE SAME
def MD5(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106020")

def MD4_T(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106030")

def SHA1(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{40}$', hash):
        jerar.append("106040")

def SHA256(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}$', hash):
        jerar.append("106060")

def SHA512(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106080")

def CRC32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106100")

def CRC32b(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106102")

def CRC32b_PHP(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106103")

def CRC32_padded(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106101")

def Adler32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106104")

def FCS32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106105")

def GHash32_3(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106106")

def GHash32_5(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106107")

def FNV132(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106108")

def Fletcher32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106109")

def Joaat(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106110")

def ELF32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106111")

def XOR32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106112")

def Microsoft_Outlook_PST(hash, jerar):
    if re.fullmatch(r'^\$PST\$.{64}$', hash) or re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106113")

def Dahua(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106114")

def NTLM(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106120")

def SHA224(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{56}$', hash):
        jerar.append("106140")

def SHA384(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{96}$', hash):
        jerar.append("106160")

def SHA3_256(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}$', hash):
        jerar.append("106180")

def SHA3_512(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106200")

def Blake2b(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106220")

def RIPEMD160(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{40}$', hash):
        jerar.append("106240")

def Whirlpool(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106260")

def argon2i(hash, jerar):
    pattern = r'^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    if bool(re.match(pattern, hash)):
        jerar.append("Argon2i(salted)")

def argon2d(hash, jerar):
    pattern = r'^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    if bool(re.match(pattern, hash)):
        jerar.append("Argon2d(salted)")

def argon2id(hash, jerar):
    pattern = r'^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    if bool(re.match(pattern, hash)):
        jerar.append("Argon2id(salted)")

def bcrypt(hash, jerar):
    if re.fullmatch(r'^\$2[ayb]\$[0-9]{2}\$[./a-zA-Z0-9]{53}$', hash):
        jerar.append("bcrypt (salted)")

def PBKDF2(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}[:][a-fA-F0-9]{32}$', hash) or re.fullmatch(r'^\$pbkdf2-[a-zA-Z0-9]+(\$[0-9]+){1}(\$[a-fA-F0-9]+){2}$', hash):
        jerar.append("PBKDF2 (salted)")

def pbkdf2_sha256(hash, jerar):
    pattern1 = r'^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'
    pattern2 = r'^[a-fA-F0-9]{64}$'
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha256 (salted)")   
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha256 (salted, hex format)")

def pbkdf2_sha1(hash, jerar):
    pattern1 = r'^pbkdf2_sha1\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'
    pattern2 = r'^[a-fA-F0-9]{40}$'
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha1 (salted)")
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha1 (salted, hex format)")

def pbkdf2_sha512(hash, jerar):
    pattern1 = r'^pbkdf2_sha512\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'
    pattern2 = r'^[a-fA-F0-9]{128}$'
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha512 (salted)")
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha512 (salted, hex format)")

def extract_salt(hash_str):
    argon2_pattern = r'^\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$([A-Za-z0-9+/]+={0,2})\$[A-Za-z0-9+/]+={0,2}$'
    match_argon2 = re.match(argon2_pattern, hash_str)
    if match_argon2:
        return match_argon2.group(1)
    else:
        return None

def decode_base64_salt(salt_base64):
    try:
        padding = len(salt_base64) % 4
        if padding != 0:
            salt_base64 += '=' * (4 - padding)
        decoded_salt = base64.b64decode(salt_base64).decode('utf-8')
        return decoded_salt
    except Exception as e:
        return f"Error decoding salt: {str(e)}"

# NEW ML INTEGRATION CLASS
class HashMLPredictor:
    def __init__(self):
        self.ml_model = None
        self.ml_loaded = False
        self.load_ml_model()
    
    # def load_ml_model(self):
    #     """Load the trained ML model"""
    #     try:
    #         model_data = joblib.load("hashtrace_ml_advanced.pkl")
    #         self.ml_model = model_data['model']
    #         self.feature_names = model_data['feature_names']
    #         self.ml_loaded = True
    #         print("🤖 ML Model Loaded Successfully!")
    #     except Exception as e:
    #         print(f"⚠️  ML Model not available: {e}")
    #         self.ml_loaded = False
    def load_ml_model(self):
        """Load the trained ML model with correct path"""
        try:
            # Get correct path to models directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            models_dir = os.path.join(project_root, "Models")
            model_path = os.path.join(models_dir, "hashtrace_ml_advanced.pkl")
            
            print(f"🔧 Looking for model at: {model_path}")
            
            if os.path.exists(model_path):
                model_data = joblib.load(model_path)
                self.ml_model = model_data['model']
                self.feature_names = model_data['feature_names']
                self.ml_loaded = True
                print("🤖 ML Model Loaded Successfully!")
            else:
                print(f"⚠️  Model file not found at: {model_path}")
                # List available files for debugging
                if os.path.exists(models_dir):
                    model_files = [f for f in os.listdir(models_dir) if f.endswith('.pkl')]
                    print(f"📁 Available model files: {model_files}")
                else:
                    print(f"❌ Models directory not found: {models_dir}")
                
        except Exception as e:
            print(f"⚠️  ML Model not available: {e}")
            self.ml_loaded = False

    
    # def predict_hash(self, hash_str):
    #     """Predict hash type using ML"""
    #     if not self.ml_loaded:
    #         return "ML_NOT_LOADED", 0.0, []
        
    #     try:
    #         features_dict = advanced_hash_features(hash_str)
    #         features_vector = [features_dict.get(key, 0) for key in self.feature_names]
    #         features_array = np.array(features_vector).reshape(1, -1)
            
    #         probabilities = self.ml_model.predict_proba(features_array)[0]
    #         predicted_class = self.ml_model.predict(features_array)[0]
    #         confidence = np.max(probabilities)
            
    #         class_indices = np.argsort(probabilities)[-3:][::-1]
    #         top_predictions = [
    #             (self.ml_model.classes_[idx], float(probabilities[idx]))
    #             for idx in class_indices
    #         ]
            
    #         return predicted_class, confidence, top_predictions
    #     except Exception as e:
    #         return f"ERROR: {str(e)}", 0.0, []

    def predict_hash(self, hash_str):
        """Predict hash type using ML with robust feature handling"""
        if not self.ml_loaded:
            return "ML_NOT_LOADED", 0.0, []
        
        try:
            # Extract features
            features_dict = advanced_hash_features(hash_str)
            features_vector = [features_dict.get(key, 0) for key in self.feature_names]
            
            # Convert boolean features to numeric (CRITICAL FIX)
            numeric_features = []
            for value in features_vector:
                if isinstance(value, bool):
                    numeric_features.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    numeric_features.append(float(value))
                elif isinstance(value, str):
                    if value.lower() in ['true', 't']:
                        numeric_features.append(1.0)
                    elif value.lower() in ['false', 'f']:
                        numeric_features.append(0.0)
                    else:
                        try:
                            numeric_features.append(float(value))
                        except:
                            numeric_features.append(0.0)
                else:
                    numeric_features.append(0.0)
            
            features_array = np.array(numeric_features).reshape(1, -1)
            
            # Clean any NaN/inf values
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            # # Debug info
            # print(f"🔧 Features extracted: {len(features_vector)}")
            # print(f"🔧 Features after conversion: {len(numeric_features)}")
            # print(f"🔧 Feature types: {[type(x) for x in numeric_features[:5]]}...")  # Show first 5 types
            
            # # Get prediction
            probabilities = self.ml_model.predict_proba(features_array)[0]
            predicted_class = self.ml_model.predict(features_array)[0]
            confidence = np.max(probabilities)
            
            # # Debug: Show prediction details
            # print(f"🔧 Raw prediction: {predicted_class}")
            # print(f"🔧 Confidence: {confidence:.4f}")
            
            class_indices = np.argsort(probabilities)[-3:][::-1]
            top_predictions = [
                (self.ml_model.classes_[idx], float(probabilities[idx]))
                for idx in class_indices
            ]
            
            # print(f"🔧 Top 3 predictions: {top_predictions}")
            
            return predicted_class, confidence, top_predictions
        except Exception as e:
            print(f"❌ ML Prediction Error: {e}")
            import traceback
            traceback.print_exc()  # This will show the full error stack
            return f"ERROR: {str(e)}", 0.0, []

# ENHANCED MAIN FUNCTION WITH FILE SUPPORT
def main():
    print(logo)
   
    # ======================= GRADIENT SHORT NAMES ==========================
    P = GRADIENTS["PURPLE_GLOW"]      # Purple
    O = GRADIENTS["ORANGE_SUNSET"]    # Orange Sunset
    G = GRADIENTS["GALAXY"]           # Galaxy Neon

    # ======================= TABLE ==========================
    cols = 3
    col_width = 35
    rows = [supported_hashes[i:i+cols] for i in range(0, len(supported_hashes), cols)]

    # Border uses Galaxy Purple-Blue mix
    border = G["G3"]

    line = border + "+" + "+".join(["-" * (col_width+2)] * cols) + "+" + RESET

    # Header uses 3 gradients
    title_row = (
        "|                                            "
        + f"{O['O3']}Supported Hash Types{RESET}".ljust(col_width)
        +  "                                                 | "

    )

    print(line)
    print(title_row)
    print(line)

    # COLUMN GRADIENTS — each column has its own unique color theme
    column_colors = [
        P["P2"],   # Column 1 → Purple Glow
        O["O4"],   # Column 2 → Orange/Gold Sunset
        G["G4"],   # Column 3 → Neon Purple Galaxy
    ]

    for row in rows:
        padded = []
        for i, h in enumerate(row):
            color = column_colors[i]
            padded.append(color + h.ljust(col_width) + RESET)

        # Fill empty cells if last row has fewer elements
        while len(padded) < cols:
            padded.append("".ljust(col_width))

        print("| " + " | ".join(padded) + " |")

    print(line)



    ml_stats_banner = display_ml_stats_banner()
    print(ml_stats_banner)
    
    # Initialize ML predictor
    ml_predictor = HashMLPredictor()        
    # Check for command line arguments
    if len(argv) > 1:
        # Handle file input
        if argv[1] in ['--file', '-f'] and len(argv) > 2:
            process_hash_file(argv[2], ml_predictor)
            return
        # Handle single hash from command line
        elif not argv[1].startswith('-'):
            process_single_hash(argv[1], ml_predictor)
            return
    
    # Original interactive mode
    try:
        first = str(argv[1]) if len(argv) > 1 else None
    except IndexError:
        first = None

    while True:
        try:
            jerar = []
            print("=" * 70)
            
            h = first if first else input("🔍 Enter Hash: ")
            
            # Process the hash
            process_single_hash(h, ml_predictor, jerar)
            
            first = None

        except KeyboardInterrupt:
            print("\n\n\t👋 Exiting. Goodbye!")
            exit()

def process_single_hash(hash_str, ml_predictor, jerar=None):
    """Process a single hash with both rule-based and ML detection"""
    if jerar is None:
        jerar = []
    
    print("=" * 70)
    
    # Run all your original hash checks
    MD5(hash_str, jerar)
    SHA1(hash_str, jerar)
    SHA256(hash_str, jerar)
    SHA512(hash_str, jerar)
    CRC32(hash_str, jerar)
    CRC32b(hash_str, jerar)
    CRC32b_PHP(hash_str, jerar)
    NTLM(hash_str, jerar)
    CRC32_padded(hash_str, jerar)
    MD4_T(hash_str, jerar)
    SHA224(hash_str, jerar)
    SHA384(hash_str, jerar)
    SHA3_256(hash_str, jerar)
    SHA3_512(hash_str, jerar)
    Blake2b(hash_str, jerar)
    RIPEMD160(hash_str, jerar)
    Whirlpool(hash_str, jerar)
    Adler32(hash_str, jerar)
    FCS32(hash_str, jerar)
    GHash32_3(hash_str, jerar)
    GHash32_5(hash_str, jerar)
    FNV132(hash_str, jerar)
    Fletcher32(hash_str, jerar)
    Joaat(hash_str, jerar)
    ELF32(hash_str, jerar)
    XOR32(hash_str, jerar)
    Microsoft_Outlook_PST(hash_str, jerar)
    Dahua(hash_str, jerar)
    bcrypt(hash_str, jerar)
    PBKDF2(hash_str, jerar)
    argon2i(hash_str, jerar)
    argon2d(hash_str, jerar)
    argon2id(hash_str, jerar)
    pbkdf2_sha256(hash_str, jerar)
    pbkdf2_sha512(hash_str, jerar)
    pbkdf2_sha1(hash_str, jerar)

    print("=" * 70)

    if len(jerar) == 0:
        print("🚫 Hash Type Not Found.")
    else:
        jerar.sort()
        print("\n🔑 Possible Hash Types:\n" + "-" * 24)
        
        # Show rule-based results (your original format)
        for i in range(min(2, len(jerar))):
            print(f"[+] {algorithms[jerar[i]]}")
        
        if len(jerar) > 2:
            print("\n🔍 Additional Possible Matches:\n" + "-" * 29)
            for i in range(2, len(jerar)):
                print(f"[+] {algorithms[jerar[i]]}")
        
        # ML Prediction
        # if ml_predictor.ml_loaded:
        #     ml_primary, ml_confidence, ml_top3 = ml_predictor.predict_hash(hash_str)
            
        #     if ml_primary != "ML_NOT_LOADED" and ml_confidence > 0:
        #         print(f"\n🧠 AI Prediction:\n" + "-" * 24)
        #         print(f"[+] {ml_primary} ({ml_confidence:.1%} confidence)")
                
        #         if ml_top3 and len(ml_top3) > 1:
        #             print(f"\n🔍 AI Top 3 Predictions:")
        #             for i, (pred, conf) in enumerate(ml_top3[:3]):
        #                 print(f"   {i+1}. {pred} ({conf:.1%})")

        # ML Prediction
    if ml_predictor.ml_loaded:
        ml_primary, ml_confidence, ml_top3 = ml_predictor.predict_hash(hash_str)
        
        # Debug: Always show ML results regardless of confidence
        print(f"\n🧠 AI Prediction Results:\n" + "-" * 24)
        print(f"Primary: {ml_primary} ({ml_confidence:.1%} confidence)")
        
        if ml_top3:
            print(f"Top 3 Predictions:")
            for i, (pred, conf) in enumerate(ml_top3[:3]):
                print(f"   {i+1}. {pred} ({conf:.1%})")
        
        # Only show as "AI Prediction" if confidence is reasonable
        if ml_confidence > 0.1:  # Lower threshold for debugging
            print(f"\n🎯 AI Final Prediction:")
            print(f"[+] {ml_primary} ({ml_confidence:.1%} confidence)")
        
        # Salt extraction for Argon2 (your original feature)
        for hash_type in jerar:
            if "argon2" in algorithms[hash_type].lower():
                print("\n🎯 Argon2 Hash Detected!")
                salt_base64 = extract_salt(hash_str)
                if salt_base64:
                    decoded_salt = decode_base64_salt(salt_base64)
                    print(f"🎉 Salt Found and Decoded: {decoded_salt}")
                else:
                    print("❌ No salt found in the Argon2 hash.")
                break

        print("=" * 70)
        print("\n🎉 Identification Complete!")
    
    print("=" * 70)

def process_hash_file(filename, ml_predictor):
    """Process multiple hashes from a file"""
    try:
        with open(filename, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        
        print(f"📁 Processing {len(hashes)} hashes from {filename}")
        print("=" * 70)
        
        results = []
        
        for i, hash_str in enumerate(hashes, 1):
            print(f"\n🔍 Hash {i}/{len(hashes)}: {hash_str}")
            print("-" * 50)
            
            jerar = []
            
            # Run rule-based detection
            MD5(hash_str, jerar)
            SHA1(hash_str, jerar)
            SHA256(hash_str, jerar)
            SHA512(hash_str, jerar)
            CRC32(hash_str, jerar)
            CRC32b(hash_str, jerar)
            CRC32b_PHP(hash_str, jerar)
            NTLM(hash_str, jerar)
            CRC32_padded(hash_str, jerar)
            MD4_T(hash_str, jerar)
            SHA224(hash_str, jerar)
            SHA384(hash_str, jerar)
            SHA3_256(hash_str, jerar)
            SHA3_512(hash_str, jerar)
            Blake2b(hash_str, jerar)
            RIPEMD160(hash_str, jerar)
            Whirlpool(hash_str, jerar)
            Adler32(hash_str, jerar)
            FCS32(hash_str, jerar)
            GHash32_3(hash_str, jerar)
            GHash32_5(hash_str, jerar)
            FNV132(hash_str, jerar)
            Fletcher32(hash_str, jerar)
            Joaat(hash_str, jerar)
            ELF32(hash_str, jerar)
            XOR32(hash_str, jerar)
            Microsoft_Outlook_PST(hash_str, jerar)
            Dahua(hash_str, jerar)
            bcrypt(hash_str, jerar)
            PBKDF2(hash_str, jerar)
            argon2i(hash_str, jerar)
            argon2d(hash_str, jerar)
            argon2id(hash_str, jerar)
            pbkdf2_sha256(hash_str, jerar)
            pbkdf2_sha512(hash_str, jerar)
            pbkdf2_sha1(hash_str, jerar)

            # ... add all other detection functions as needed
            
            # Get ML prediction
            ml_primary, ml_confidence, ml_top3 = ml_predictor.predict_hash(hash_str)
            
            # Store results
            rule_based = [algorithms.get(j, j) for j in jerar[:3]] if jerar else ["Unknown"]
            ml_best = ml_primary if ml_confidence > 0.6 else "Low confidence"
            
            results.append({
                'hash': hash_str,
                'rule_based': rule_based,
                'ml_prediction': ml_best,
                'ml_confidence': ml_confidence
            })
            
            # Display results for this hash
            if jerar:
                print("🔑 Rule-Based:")
                for algo in rule_based[:3]:
                    print(f"   • {algo}")
            
            if ml_confidence > 0:
                print(f"🧠 AI: {ml_primary} ({ml_confidence:.1%})")
            
            print("-" * 50)
        
        # Summary
        print("\n" + "=" * 70)
        print("📊 FILE ANALYSIS SUMMARY")
        print("=" * 70)
        
        ml_confident = sum(1 for r in results if r['ml_confidence'] > 0.7)
        print(f"✅ Hashes with confident ML predictions: {ml_confident}/{len(results)}")
        
        unique_types = set()
        for r in results:
            if r['ml_confidence'] > 0.7:
                unique_types.add(r['ml_prediction'])
            for algo in r['rule_based']:
                unique_types.add(algo)
        
        print(f"🔍 Unique hash types found: {len(unique_types)}")
        if unique_types:
            print(f"📋 Types: {', '.join(sorted(unique_types)[:10])}{'...' if len(unique_types) > 10 else ''}")
        
    except FileNotFoundError:
        print(f"❌ File not found: {filename}")
    except Exception as e:
        print(f"❌ Error processing file: {e}")

# Add command line help
# Update the help section at the bottom
if __name__ == "__main__":
    # Check for help flag
    if len(argv) > 1 and argv[1] in ['--help', '-h']:
        print("HashTrace Advanced - Hash Identification Tool")
        print("\nUsage:")
        print("  python hashtrace_ml.py                    # Interactive mode")
        print("  python hashtrace_ml.py <hash>            # Analyze single hash")
        print("  python hashtrace_ml.py --file <filename> # Analyze hashes from file")
        print("  python hashtrace_ml.py -f <filename>     # Short version")
        print("\nExamples:")
        print("  python hashtrace_ml.py 5d41402abc4b2a76b9719d911017c592")
        print("  python hashtrace_ml.py --file hashes.txt")
        exit()
    
    main()