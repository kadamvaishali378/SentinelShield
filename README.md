# 🛡️ SentinelShield

### Advanced Intrusion Detection & Web Protection System

---

## 📌 Project Description

SentinelShield is a web security monitoring system that analyzes incoming HTTP requests and detects malicious activities such as Cross-Site Scripting (XSS), SQL Injection, Directory Traversal, and Command Injection.

The system also implements rate limiting to identify suspicious behavior such as brute-force attacks. It logs all security events and provides a dashboard for visualizing system activity.

---

## 🎯 Objectives

* Inspect incoming HTTP requests
* Detect malicious attack patterns
* Monitor request behavior (rate limiting)
* Log security events
* Visualize system activity using a dashboard

---

## 🚨 Problem Statement

Web applications are frequently targeted by cyber attacks such as XSS, SQL Injection, and Command Injection. Many systems lack proper monitoring, allowing malicious activities to go undetected.

SentinelShield addresses this by analyzing request data and detecting suspicious patterns using intrusion detection techniques.

---

## ✨ Features

* Detects common web attacks:

  * Cross-Site Scripting (XSS)
  * SQL Injection
  * Directory Traversal
  * Command Injection
* Rate limiting for brute-force detection
* Logs all requests and security events
* Dashboard for attack visualization
* Lightweight Flask-based system

---

## 🛠️ Technologies Used

* Python
* Flask
* Python Logging Module
* Chart.js
* Web Browser (Chrome)

---

## ⚙️ Installation & Setup

1. Install Python
2. Install Flask:

   ```bash
   pip install flask
   ```
3. Run the application:

   ```bash
   python app.py
   ```
4. Open browser:

   ```
   http://127.0.0.1:5000
   ```

---

## ▶️ How to Use

### 🔹 Normal Request

```
http://127.0.0.1:5000/inspect?name=hello
```

### 🔹 XSS Attack

```
http://127.0.0.1:5000/inspect?search=<script>alert(1)</script>
```

### 🔹 SQL Injection

```
http://127.0.0.1:5000/inspect?id=1 or 1=1
```

### 🔹 Directory Traversal

```
http://127.0.0.1:5000/inspect?file=../../etc/passwd
```

### 🔹 Command Injection

```
http://127.0.0.1:5000/inspect?cmd=whoami
```

---

## 🧠 Detection Techniques

### 1. Signature-Based Detection

Detects attacks using predefined patterns:

* `<script>` → XSS
* `or 1=1` → SQL Injection
* `../` → Directory Traversal
* `cmd` → Command Injection

### 2. Behavior-Based Detection

* Tracks request frequency
* Detects brute-force or automated attacks
* Uses rate limiting based on IP

---

## 🏗️ System Architecture

Main components:

* User Request Interface
* Flask Web Server
* Request Inspection Engine
* Attack Detection Module
* Rate Limiting Module
* Logging System
* Security Dashboard

---

## 🔄 Workflow

1. User sends HTTP request
2. Flask server receives request
3. Query parameters extracted
4. Attack signatures checked
5. Rate limiting applied
6. Request classified (Normal / Malicious)
7. Event logged
8. Dashboard updated

---

## 📊 Output / Results

* Requests classified as Normal or Malicious
* Attack type identified
* Logs stored in `sentinelshield.log`
* Dashboard displays:

  * Total requests
  * Malicious requests
  * Attack distribution

---

## 📁 Project Structure

```
/sentinelshield
│── app.py
│── sentinelshield.log
│── templates/
│── static/
```

---

## ✅ Advantages

* Detects common web attacks
* Logs security events
* Visual dashboard for monitoring
* Demonstrates real-world IDS concepts
* Easy to understand and implement

---

## ⚠️ Limitations

* Detects only predefined attack patterns
* Cannot detect zero-day attacks
* Designed for educational purposes

---

## 🚀 Future Scope

* Add machine learning detection
* Improve dashboard analytics
* Add real-time alerts
* Integrate threat intelligence
* Detect advanced attack types

---

## 📚 Learning Outcomes

* Understanding HTTP request analysis
* Detecting malicious payloads
* Implementing intrusion detection
* Log monitoring and analysis
* Security data visualization

---

## 🏁 Conclusion

SentinelShield demonstrates how intrusion detection systems monitor web traffic, detect malicious inputs, and log security events. It provides practical insight into cybersecurity monitoring techniques used in real-world environments.

---

## 📦 Project Deliverables

* Python application code
* Security log file
* Dashboard
* System diagrams
* Documentation report

---

## 📖 References

* OWASP Top 10 – https://owasp.org
* Flask Documentation – https://flask.palletsprojects.com
* Python Logging – https://docs.python.org
* Chart.js – https://www.chartjs.org

---

## 👩‍💻 Author

**Vaishali Vasant Kadam**
Cyber Security Internship Project
Submission Date: 22 March 2026

---
