# 🔐 Secure Research Dataset Sharing System (Production Backend Project)

## 📌 Project Overview

The **Secure Research Dataset Sharing System** is a production-level web platform designed to securely share sensitive research datasets with controlled and time-limited access.

The system ensures **data confidentiality, integrity, and authorized usage** through multi-layer authentication, role-based access control, and hybrid encryption techniques (AES + RSA). It enables researchers to upload encrypted datasets, allows authorized users to access them within a defined time period, and protects data using secure authentication and verification mechanisms.

This platform is suitable for academic institutions, research organizations, and secure data-sharing environments where privacy and controlled access are critical.

---

## 🎯 Objectives

* Implement secure dataset sharing with controlled access.
* Ensure data confidentiality using hybrid encryption.
* Provide role-based access control for different users.
* Enable time-limited dataset availability.
* Implement strong authentication and authorization mechanisms.
* Maintain dataset integrity using digital signatures.

---

## ⚙️ Tech Stack

* **Python**
* **Flask (Backend Framework)**
* **MongoDB (Database)**
* **HTML, CSS, JavaScript (Frontend)**
* **JWT Authentication**
* **AES Encryption (Data Security)**
* **RSA Encryption (Key Exchange)**
* **SHA-256 Hashing (Password Security)**
* **Redis (Caching)**
* **Docker (Containerization)**
* **AWS S3 / MinIO (Cloud Storage)**
* **SMTP Email Verification**

---

## ⭐ Key Features

### 🔐 Secure Authentication

* JWT-based authentication
* Email OTP verification
* Multi-layer login security
* Token-based session management

### 👥 Role-Based Access Control

* **Admin** → manages users and system logs
* **Researcher** → uploads and shares datasets
* **Reviewer** → accesses shared datasets

### 🛡 Hybrid Encryption Security

* AES encryption for dataset files
* RSA encryption for secure key exchange
* End-to-end data protection

### 🔑 Password Protection

* SHA-256 hashing with salt
* Secure credential storage
* Protection against password theft

### ✍️ Digital Signature Verification

* Ensures dataset authenticity
* Prevents data tampering
* Validates data integrity

### ⏳ Time-Limited Dataset Access

* Controlled dataset availability period
* Automatic access expiration
* Secure data usage enforcement

### ☁️ Secure Cloud Storage

* AWS S3 / MinIO integration
* Secure file upload and download
* Encrypted storage access

---

## 🚀 Production-Level Backend Architecture

* REST API architecture
* Docker containerization
* Redis caching
* Rate limiting and brute-force protection
* Secure API endpoints
* Token-based authorization

---

## 🖥️ System Architecture

```
Client → JWT Authentication → Flask API → Redis Cache → MongoDB → Secure Storage (S3/MinIO)
```

---

## 📡 API Capabilities

* Secure dataset upload API
* Dataset access authorization API
* Role-based API permissions
* Authentication and token verification endpoints

---

## 📊 Security Mechanisms

* Hybrid encryption (AES + RSA)
* Password hashing with SHA-256
* Digital signature verification
* Rate limiting protection
* Secure token management

---

## ▶️ How to Run the Project

### 1️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 2️⃣ Configure Environment Variables

Create a `.env` file and add required credentials.

### 3️⃣ Run the Server

```bash
python app.py
```

### 4️⃣ Open in Browser

```
http://127.0.0.1:5000
```

---

## 📸 Example Input

![Secure_Research_project](p1-project.png)
![Secure_Research_project](p2-project.png)
![Secure_Research_project](p3-project.png)
![Secure_Research_project](p4-project.png)


---

## 📊 Project Highlights (Resume Value)

* Production-level backend system design
* JWT authentication implementation
* Hybrid encryption architecture
* Role-based authorization system
* Secure dataset sharing platform
* Cloud storage integration
* Security-focused backend engineering

---

## ⚠️ Limitations

* Requires proper environment configuration.
* Depends on external cloud storage services.
* Designed for controlled research environments.

---

## 🚀 Future Improvements

* Multi-factor authentication support.
* Blockchain-based dataset verification.
* Microservices architecture.
* Large-scale distributed deployment.
* Advanced monitoring and logging system.

---

## 👨‍💻 Author

**Hemanth Gudi**
Computer Science Student | Full Stack Developer | Backend Engineer
