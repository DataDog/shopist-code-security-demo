require 'stripe'
require 'aws-sdk-s3'
require 'pg'

# VULN 1: Hardcoded Stripe secret key - exposes live payment processing credentials
def configure_stripe
  Stripe.api_key = "sk_live_51HqT3gJKL9mNpR2xWvYzAb3CdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
  Stripe::Charge.create(
    amount: 5000,
    currency: "usd",
    source: "tok_visa",
    description: "Shopist order payment"
  )
end

# VULN 2: Hardcoded AWS credentials in S3 client - exposes cloud storage access
def upload_invoice_to_s3(invoice_pdf, order_id)
  s3 = Aws::S3::Client.new(
    region: 'us-east-1',
    access_key_id: 'AKIAIOSFODNN7EXAMPLE',
    secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  )
  s3.put_object(
    bucket: 'shopist-invoices',
    key: "invoices/#{order_id}.pdf",
    body: invoice_pdf
  )
end

# VULN 3: Hardcoded DB password in connection string - exposes database credentials
def get_payment_db_connection
  conn = PG.connect(
    host: 'payments-db.shopist.internal',
    dbname: 'shopist_payments',
    user: 'payments_user',
    password: 'Sh0p1st$Payments#Pr0d2024!'
  )
  conn
end
