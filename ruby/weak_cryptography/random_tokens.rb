require 'active_record'

# VULN 1: rand() for password reset token - non-CSPRNG, predictable with timing information
def generate_password_reset_token(user_id)
  token = rand(36**32).to_s(36)
  User.find(user_id).update(
    reset_token: token,
    reset_token_expires_at: Time.now + 3600
  )
  token
end

# VULN 2: rand() for email confirmation code - only 900000 possibilities, brute-forceable
def generate_email_confirmation_code(user_id)
  code = rand(100000..999999)
  User.find(user_id).update(
    confirmation_code: code,
    confirmation_code_expires_at: Time.now + 600
  )
  code.to_s
end

# VULN 3: Seeded Random with user_id for CSRF token - deterministic, attacker can reproduce
def generate_csrf_token(user_id)
  rng = Random.new(user_id)
  token = rng.bytes(16).unpack1('H*')
  token
end
