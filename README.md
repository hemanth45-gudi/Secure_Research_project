# 🔐 Secure Research Dataset Sharing System (Production-Ready Backend System)

## 📌 Project Overview
The **Secure Research Dataset Sharing System** is a production-ready web platform designed to securely share sensitive research datasets with controlled and time-limited access.

The system ensures **data confidentiality, integrity, and authorized usage** through multi-layer authentication, role-based access control, and hybrid encryption (AES + RSA). It allows researchers to upload encrypted datasets, enables authorized users to access them within defined time limits, and protects data using secure verification mechanisms.

This platform is suitable for academic institutions, research organizations, and secure data-sharing environments where privacy and controlled access are critical.

---

## 🎯 Objectives
- Implement secure dataset sharing with controlled access  
- Ensure data confidentiality using hybrid encryption  
- Provide role-based access control  
- Enable time-limited dataset availability  
- Implement strong authentication and authorization  
- Maintain dataset integrity using digital signatures  

---

## ⚙️ Tech Stack
- **Backend:** Flask (Python)  
- **Database:** MongoDB  
- **Frontend:** HTML, CSS, JavaScript  
- **Authentication:** JWT, Email OTP Verification  
- **Security:** AES Encryption, RSA Encryption, SHA-256 Hashing  
- **Caching:** Redis  
- **Cloud Storage:** AWS S3 / MinIO  
- **Testing:** Pytest, MongoMock  
- **Containerization:** Docker  
- **CI/CD:** GitHub Actions  
- **API Docs:** Swagger / OpenAPI  

---

## ⭐ Key Features

### 🔐 Secure Authentication
- JWT-based authentication  
- Email OTP verification  
- Token-based session management  
- Multi-layer login security  

### 👥 Role-Based Access Control
- **Admin** → manages users and logs  
- **Researcher** → uploads and shares datasets  
- **Reviewer** → accesses shared datasets  

### 🛡 Hybrid Encryption Security
- AES encryption for dataset files  
- RSA encryption for key exchange  
- End-to-end data protection  

### 🔑 Password Protection
- SHA-256 hashing with salt  
- Secure credential storage  

### ✍️ Digital Signature Verification
- Ensures dataset authenticity  
- Prevents data tampering  
- Validates data integrity  

### ⏳ Time-Limited Dataset Access
- Controlled dataset availability period  
- Automatic access expiration  

### ☁️ Secure Cloud Storage
- AWS S3 / MinIO integration  
- Secure file upload and download  
- Encrypted storage access  

---

## 🏭 Production Features
- REST API architecture  
- Modular backend structure (API → Services → Core)  
- Centralized logging and audit logs  
- Rate limiting and brute-force protection  
- Request validation and error handling  
- Docker containerization  
- Redis caching  
- Health check endpoint (`/health`)  
- GitHub Actions CI/CD pipeline  
- Automated unit and integration testing  

---

## 🖥️ System Architecture
```
Client → Flask API → Authentication → Redis Cache → MongoDB → Secure Storage (S3/MinIO)
```

---

## 📘 API Documentation
Swagger UI available at:

```
http://127.0.0.1:5000/api/docs
```

---

## 🧪 Testing & CI/CD
- Pytest unit and integration tests  
- MongoMock database isolation  
- GitHub Actions automated testing pipeline  
- Linting with flake8  

Run tests:
```
pytest
```

---

## 🚀 How to Run the Project

### Option 1 — Docker (Recommended)
```
docker-compose up --build
```

### Option 2 — Manual Setup

#### 1️⃣ Install Dependencies
```
pip install -r requirements.txt
```

#### 2️⃣ Configure Environment Variables
Create a `.env` file and add required credentials.

#### 3️⃣ Run Server
```
python app.py
```

#### 4️⃣ Open in Browser
```
http://127.0.0.1:5000
```

---

## 📸 Screenshots

![Dashboard Screenshot]("p1-project.png")
![Dashboard Screenshot]("p2-project.png")
![Dashboard Screenshot]("p3-project.png")
![Dashboard Screenshot]("p4-project.png")
![Dashboard Screenshot]("p5-project.png")
![Dashboard Screenshot]("p6-project.png")

---

## 📊 Project Highlights (Resume Value)
- Production-ready backend system design  
- Secure dataset sharing platform  
- Hybrid encryption architecture  
- JWT authentication implementation  
- Role-based authorization system  
- Cloud storage integration  
- Security-focused backend engineering  

---

## ⚠️ Limitations
- Requires proper environment configuration  
- Depends on external cloud storage services  
- Designed for controlled research environments  

---

## 🚀 Future Improvements
- Multi-factor authentication (MFA)  
- Advanced monitoring and metrics (Prometheus/Grafana)  
- Microservices architecture  
- Large-scale distributed deployment  
- Blockchain-based dataset verification  

---

## 👨‍💻 Author
**Hemanth Gudi**  
Computer Science Student | Backend Developer | Full Stack Developer
