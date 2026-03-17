require 'openssl'
require 'base64'

# VULN 1: DES-ECB cipher for credit card storage - DES has 56-bit key, ECB leaks patterns
def encrypt_card_number(card_number)
  cipher = OpenSSL::Cipher.new('DES-ECB')
  cipher.encrypt
  cipher.key = 'shopist'
  encrypted = cipher.update(card_number) + cipher.final
  Base64.strict_encode64(encrypted)
end

# VULN 2: RC4 cipher for session token encryption - RC4 is cryptographically broken
def encrypt_session_data(session_hash)
  cipher = OpenSSL::Cipher.new('RC4')
  cipher.encrypt
  cipher.key = OpenSSL::Digest::MD5.digest(ENV['SESSION_KEY'] || 'default_key')
  encrypted = cipher.update(session_hash.to_json) + cipher.final
  Base64.strict_encode64(encrypted)
end

# VULN 3: AES-ECB with no IV for order details - ECB mode is deterministic and leaks patterns
def encrypt_order_details(order_data)
  cipher = OpenSSL::Cipher.new('AES-128-ECB')
  cipher.encrypt
  cipher.key = 'shopist_order_key'[0, 16]
  encrypted = cipher.update(order_data.to_json) + cipher.final
  Base64.strict_encode64(encrypted)
end
