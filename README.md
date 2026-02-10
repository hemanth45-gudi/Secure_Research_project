Project Name : Secure Research Dataset Sharing System with Time-Limited Access

Secure Research Portal is a Flask-based web application for securely managing and sharing research datasets. It implements multi-factor authentication (password + email OTP), role-based access control (Admin, Researcher, Reviewer), and hybrid encryption using AES and RSA. Passwords are protected using SHA-256 hashing with salt, and digital signatures ensure data integrity and authenticity. MongoDB is used for secure storage of users, datasets, and activity logs.

Tech Stack:
JavaScript,
HTML,
CSS,
React,
Tailwind CSS,
Node.js,
Express.js,
MongoDB,


Features : 
 Multi-Factor Authentication (Password + Email OTP)   ,
 Role-Based Access Control (Admin, Researcher, Reviewer)  , 
 Hybrid Encryption (AES for data + RSA for key exchange)   ,
 Secure Password Storage using SHA-256   ,
 Secure Dataset Upload & Download   , 
 Time-Limited Dataset Access ,
 Activity Logging and Monitoring

How to Run the Project: 
pip install -r requirements.txt
python app.py  
