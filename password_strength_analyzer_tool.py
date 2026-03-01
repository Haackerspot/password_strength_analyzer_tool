import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty",
    "admin", "letmein", "welcome", "raj@123"
}

def detect_patterns(password):
    if re.search(r"(.)\1{2,}", password):
        return "Repeated characters detected"
    if re.search(r"123|abc|qwerty", password.lower()):
        return "Sequential pattern detected"
    return None


def estimate_hash_crack_time(seconds, algo):
    factors = {
        "bcrypt": 1_000,
        "pbkdf2": 5_000,
        "argon2": 20_000
    }
    return seconds * factors.get(algo, 1)


def password_strength(password):
    report = {}
    length = len(password)

    lower = bool(re.search(r"[a-z]", password))
    upper = bool(re.search(r"[A-Z]", password))
    digit = bool(re.search(r"\d", password))
    symbol = bool(re.search(r"[!@#$%^&*()_+=\-[\]{};':\"\\|,.<>/?]", password))

    charset = 0
    if lower: charset += 26
    if upper: charset += 26
    if digit: charset += 10
    if symbol: charset += 32

    entropy = length * math.log2(charset) if charset else 0

    guesses_per_second = 10_000_000_000
    combinations = charset ** length if charset else 0
    seconds = combinations / guesses_per_second if combinations else 0
    years = seconds / (60 * 60 * 24 * 365)

    # Dictionary check
    dictionary_flag = password.lower() in COMMON_PASSWORDS

    # Pattern check
    pattern_issue = detect_patterns(password)

    # Strength classification
    if entropy < 30 or dictionary_flag:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    report["Password Length"] = length
    report["Entropy (bits)"] = round(entropy, 2)
    report["Strength"] = strength
    report["Brute-Force Crack Time (years)"] = round(years, 4)
    report["Dictionary Password"] = "Yes" if dictionary_flag else "No"
    report["Pattern Issue"] = pattern_issue if pattern_issue else "None"

    # Hash-based estimation
    report["bcrypt Crack Time (years)"] = round(
        estimate_hash_crack_time(years, "bcrypt"), 2)
    report["PBKDF2 Crack Time (years)"] = round(
        estimate_hash_crack_time(years, "pbkdf2"), 2)
    report["Argon2 Crack Time (years)"] = round(
        estimate_hash_crack_time(years, "argon2"), 2)

    # Recommendations
    recommendations = []
    if length < 12:
        recommendations.append("Increase password length to at least 12 characters.")
    if not symbol:
        recommendations.append("Add special characters.")
    if not upper:
        recommendations.append("Include uppercase letters.")
    if dictionary_flag:
        recommendations.append("Avoid common or leaked passwords.")
    if pattern_issue:
        recommendations.append("Avoid predictable patterns.")

    report["Security Recommendations"] = recommendations or ["Password is well-structured."]

    return report


# ===== MAIN =====
password = input("Enter password to analyze: ")
result = password_strength(password)

print("\n🔐 Password Security Analysis Report")
print("-" * 45)
for key, value in result.items():
    print(f"{key}: {value}")
