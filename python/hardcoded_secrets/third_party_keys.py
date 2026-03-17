import requests


# VULN 1: Hardcoded SendGrid API key for marketing emails
def send_promotional_email(to_email, promo_code):
    api_key = "SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.1234567890abcdefghijklmnopqrstuvwxyz12345"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    data = {"to": to_email, "subject": "Your promo code", "text": f"Use {promo_code}"}
    requests.post("https://api.sendgrid.com/v3/mail/send", json=data, headers=headers)


# VULN 2: Hardcoded Google Maps API key for store locator
def get_store_location(address):
    GOOGLE_MAPS_KEY = "AIzaSyD-9tSrke72I6oP123456789abcdefghijk"
    url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={GOOGLE_MAPS_KEY}"
    return requests.get(url).json()


# VULN 3: Hardcoded Twilio credentials for SMS notifications
def send_shipping_sms(phone_number, tracking_number):
    account_sid = "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    auth_token = "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6"
    from twilio.rest import Client
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=f"Your order shipped! Track: {tracking_number}",
        from_="+15551234567",
        to=phone_number,
    )
