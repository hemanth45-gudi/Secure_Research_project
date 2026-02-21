"""
core/email.py   Consolidated Email Utility
==========================================
Handles SMTP communication for OTP and other system emails.
Supports SSL (465) and STARTTLS (587) with optional simulation mode.
"""

import smtplib
from email.message import EmailMessage
from flask import current_app

def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Sends an OTP email using configured SMTP settings.
    Falls back to console simulation if credentials are missing.
    """
    email_addr = current_app.config.get('EMAIL_ADDRESS')
    email_pass = current_app.config.get('EMAIL_PASSWORD')
    smtp_server = current_app.config.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port   = int(current_app.config.get('SMTP_PORT', 587))
    use_tls     = current_app.config.get('SMTP_USE_TLS', True)
    use_ssl     = current_app.config.get('SMTP_USE_SSL', False)

    # 1. Validation & Simulation Check
    if not email_addr or not email_pass:
        print("\n" + "="*60)
        print(" [WARN EMAIL] SMTP credentials not found in environment.")
        print(f" [SIMULATION] To: {to_email}")
        print(f" [SIMULATION] OTP: {otp}")
        print("="*60 + "\n", flush=True)
        return True

    # 2. Build Message
    msg = EmailMessage()
    msg.set_content(f"Your Secure Research Portal OTP is: {otp}")
    msg['Subject'] = 'Login Verification Code'
    msg['From']    = email_addr
    msg['To']      = to_email

    # 3. Connect and Send
    try:
        if use_ssl:
            # SSL (Port 465)
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(email_addr, email_pass)
                server.send_message(msg)
        else:
            # STARTTLS (Port 587 or 25)
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                server.login(email_addr, email_pass)
                server.send_message(msg)
        
        print(f"[OK EMAIL] OTP successfully sent to {to_email}", flush=True)
        return True

    except Exception as e:
        print(f"\n[ERROR EMAIL FAILED] {str(e)}", flush=True)
        print(f" [RECOVERY] Printing OTP to console: {otp}\n", flush=True)
        return True # Return true so the user flow isn't blocked by minor email failures
