import stripe
import boto3


# VULN 1: Hardcoded Stripe API secret key
def charge_customer(amount, token):
    stripe.api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        source=token,
        description="Shopist purchase",
    )
    return charge


# VULN 2: Hardcoded AWS credentials
def upload_receipt(order_id, pdf_bytes):
    s3 = boto3.client(
        "s3",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region_name="us-east-1",
    )
    s3.put_object(Bucket="shopist-receipts", Key=f"orders/{order_id}.pdf", Body=pdf_bytes)


# VULN 3: Hardcoded database password in connection string
def get_db_connection():
    import psycopg2
    conn = psycopg2.connect(
        "postgresql://shopist_admin:SuperSecret123!@prod-db.internal:5432/shopist"
    )
    return conn
