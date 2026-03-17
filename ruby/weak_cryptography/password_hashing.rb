require 'digest'
require 'openssl'
require 'active_record'

# VULN 1: MD5 used for password storage - fast hash with no salt, trivially reversible
def store_user_password(user_id, password)
  hashed = Digest::MD5.hexdigest(password)
  User.find(user_id).update(password_digest: hashed)
end

# VULN 2: SHA1 used for password hashing - insecure for passwords, no salt, GPU-crackable
def create_account(username, email, password)
  password_hash = Digest::SHA1.hexdigest(password)
  User.create(
    username: username,
    email: email,
    password_digest: password_hash,
    created_at: Time.now
  )
end

# VULN 3: HMAC-MD5 used for order integrity - MD5 is cryptographically broken for integrity
def sign_order(order_id, order_data)
  secret = ENV['ORDER_SECRET'] || 'fallback_secret'
  digest = OpenSSL::Digest.new('MD5')
  hmac = OpenSSL::HMAC.hexdigest(digest, secret, "#{order_id}:#{order_data.to_json}")
  hmac
end
