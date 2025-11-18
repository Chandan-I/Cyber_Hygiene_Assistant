🛡 Cyber Hygiene Assistant

A smart, Windows-based security assessment tool designed to help users scan, analyze, and improve their system’s cyber hygiene. Ideal for beginners, students, and professionals who want a simple yet powerful way to keep their system secure.

📘 Overview

Cyber Hygiene Assistant is an all-in-one GUI application built to evaluate a system’s security posture. It scans for vulnerabilities, reviews system configuration, inspects open ports, and generates structured reports. It also includes an interactive cybersecurity quiz to help users strengthen their knowledge.

The tool uses native Windows utilities and commands safely, without collecting or transmitting personal data.

✨ Features
🔍 System Security Scan

Performs an in-depth check of key security components:

Auto-Login Status: Detects if Windows automatically logs in a user (unsafe).

Antivirus Detection: Confirms active antivirus protection (Windows Defender or third-party).

OS Update Status: Verifies Windows Update service and recent patching.

Wi-Fi Security: Checks encryption type (WEP/Open = insecure).

Firewall Profiles: Reports firewall status across Public, Private, and Domain networks.

Open Ports: Lists listening ports using netstat -ano and identifies processes.

Each category produces a score (0–100) and recommendations.

🖥 GUI Layout

The interface is simple and intuitive:

Left Panel

🔍 Security Scan

❓ Quiz

🔌 Open Ports (visible after scan)

Right Panel

▶ Run Scan

📂 Export CSV

📑 Open Last Report

📘 Manual

🚀 How to Use
1. Run a Scan

Click Run Scan to perform a security check.
After completion, the Open Ports tab becomes available.

2. Review Findings

You will see:

Configuration checks

Scores and explanations

Detected vulnerabilities

Security recommendations

3. Inspect/Open Ports

The Open Ports tab shows:

IP address and port

PID

Process name

Linked Windows services

You can safely close suspicious ports directly from the interface.

4. Export or Reload Results

Export CSV: Save the full scan report

Open Last Report: Load your most recent analysis

📂 Reports

Every scan can be exported as a CSV report containing:

System name

Scan categories and scores

Evidence and explanations

Recommendations

Detected open ports

This makes it suitable for:

IT audits

Training & documentation

Security progress tracking

❓ Cybersecurity Quiz

A built-in quiz to strengthen user awareness.

Features:

10 random non-repeating questions

Instant feedback

Score tracking

Simple and educational

Great for learners and certification aspirants.

🔒 Security & Privacy

No personal data leaves the device

Uses safe Windows commands

Allows users to choose when to close ports or export data

Designed for transparency and user control

Requirements

Windows OS

Administrator privileges recommended for full port visibility

Python + libraries (if applicable, depending on your implementation)

📦 Installation
git clone https://github.com/your-repo/cyber-hygiene-assistant
cd cyber-hygiene-assistant
pip install -r requirements.txt
python main.py

🙌 Acknowledgements

Thanks to my team members who helped develop the Cyber Hygiene Assistant.
Stay safe — practice cyber hygiene daily! 🔐
