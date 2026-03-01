🔐 Advanced Password Strength Analyzer

An advanced Python-based Password Strength Analyzer that evaluates password security using entropy calculation, brute-force crack time estimation, dictionary checks, and pattern detection.

This project demonstrates practical cybersecurity concepts such as entropy analysis, attack simulation, and secure password recommendations.

📌 Project Overview

    This tool analyzes a password using multiple security parameters:
    Character diversity
    Entropy calculation (bits)
    Brute-force crack time estimation
    Common password detection 
    Sequential & repeated pattern detection
    Hash algorithm crack-time simulation (bcrypt, PBKDF2, Argon2)
    Security recommendations

The goal is to simulate how attackers evaluate password strength and educate users on building stronger passwords.


🧠 Security Concepts Implemented

🔢 1. Entropy Calculation
         
    Entropy is calculated using:
    Entropy = Length × log2(Character Set Size)
Higher entropy means higher unpredictability.

🔐 2. Character Set Detection
   The analyzer detects:
    Lowercase letters (26)
    Uppercase letters (26)
    Digits (10)
    Symbols (32 estimated)
The total charset size directly impacts entropy and brute-force resistance.

🚨 3. Dictionary Password Detection
The tool checks against a predefined list of common passwords:
     password, 123456, 12345678, qwerty, admin, letmein, welcome, raj@123
If matched → Automatically classified as Weak.


🔁 4. Pattern Detection

Detects:
    
    Repeated characters (e.g., aaa, 1111) 
    Sequential patterns (e.g., 123, abc, qwerty)
This prevents predictable password structures.

    
⏳ 5. Brute-Force Crack Time Estimation

The tool simulates attack speed:
    10 Billion guesses per second
    Calculates total combinations
    Converts time into years
        Combinations = charset ^ length

        
🔑 6. Hash-Based Crack Time Simulation

Simulates stronger protection using:
     bcrypt (×1,000 resistance factor) 
     PBKDF2 (×5,000 resistance factor)
     Argon2 (×20,000 resistance factor)
This demonstrates how slow-hashing algorithms improve security.


📊 Strength Classification Logic

     Entropy (bits)               Strength
    < 30 or dictionary match	    Weak
     30 – 59                    	Medium
     60 – 79	                    Strong
     80+                          Very Strong


🛠 Technologies Used
      
    Python 3.x
    math module (entropy calculations)
    re module (pattern detection)
    CLI-based interface

📂 Project Structure
password-strength-analyzer/
│
├── password_analyzer.py
└── README.md


🚀 Installation & Usage
1️⃣ Clone Repository
git clone (https://github.com/Haackerspot/password_strength_analyzer_too)
cd password-strength-analyzer


2️⃣ Run the Program
python password_analyzer.py


3️⃣ Enter Password
Enter password to analyze: MySecurePass@123


🖥 Example Output
🔐 Password Security Analysis Report
---------------------------------------------
Password Length: 15
Entropy (bits): 98.32
Strength: Very Strong
Brute-Force Crack Time (years): 15432.2231
Dictionary Password: No
Pattern Issue: None
bcrypt Crack Time (years): 15432223.23
PBKDF2 Crack Time (years): 77161116.15
Argon2 Crack Time (years): 308644464.6
Security Recommendations: ['Password is well-structured.']


🛡 Security Recommendations Provided By Tool

    Increase password length to at least 12 characters
    Add special characters
    Include uppercase letters
    Avoid dictionary passwords
    Avoid predictable patterns
    

🎯 Why This Project Matters

    This tool demonstrates real-world defensive cybersecurity concepts:
    How attackers estimate cracking feasibility
    Why entropy matters
    Why hashing algorithms slow down attacks
    Why dictionary passwords are dangerous
    How predictable patterns weaken passwords
    

📈 Future Improvements

    Add entropy graph visualization
    Integrate real breached password API
    Add password generator
    Add GUI version (Tkinter)
    Convert to Web App (Flask/FastAPI)
    Add JSON export report
    Add unit testing


🎓 Ideal For

    Cybersecurity portfolios
    Ethical hacking students
    Python security developers
    Internship applications
    Academic cybersecurity projects

⚠ Disclaimer

This tool is for educational and awareness purposes only.
It does not store, transmit, or log passwords.

👨‍💻 Author

HAACKERSPOT AKA RAJ SINGH
Cybersecurity Enthusiast | Python Security Projects | Network Security Learner







