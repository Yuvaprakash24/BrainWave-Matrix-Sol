import re
from typing import Tuple, Dict

COMMON_PASSWORDS = {
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password1', '12345678', '111111', '1234567', 'sunshine', '00000000'
}

def password_strength_checker(password: str) -> Dict[str, str]:
    feedback = []
    score = 0
    
    length = len(password)
    if length < 8:
        feedback.append("Password is too short. Use at least 8 characters.")
    elif length <= 12:
        feedback.append("Password length is moderate. Consider using more than 12 characters for better security.")
        score += 1
    else:
        feedback.append("Password length is strong.")
        score += 2
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters for better security.")
        
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters for better security.")
        
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add numbers for better security.")
        
    if re.search(r'[\W_]', password):
        score += 1
    else:
        feedback.append("Add special characters (e.g., @, #, $, etc.) for better security.")
    
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("Password is too common. Choose a more unique password.")
    else:
        score += 1
    
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid using sequences of repeated characters.")
    else:
        score += 1
    
    if score <= 3:
        strength = "Weak"
    elif score <= 5:
        strength = "Moderate"
    else:
        strength = "Strong"
    
    return {
        "strength": strength,
        "feedback": " ".join(feedback)
    }

password = input()
result = password_strength_checker(password)
print(f"Password Strength: {result['strength']}")
print(f"Feedback: {result['feedback']}")