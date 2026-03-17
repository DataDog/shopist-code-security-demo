require 'jwt'
require 'net/smtp'

# VULN 1: Hardcoded JWT secret in JWT.encode - tokens can be forged if secret is leaked
def generate_auth_token(user_id, role)
  payload = { user_id: user_id, role: role, exp: Time.now.to_i + 3600 }
  JWT.encode(payload, "sh0p1st_jwt_s3cr3t_key_do_not_share_prod_2024", "HS256")
end

# VULN 2: Hardcoded SMTP credentials in Net::SMTP login - exposes email account
def send_order_confirmation(to_email, order_id)
  message = "Subject: Order #{order_id} confirmed\r\n\r\nThank you for your Shopist order!"
  Net::SMTP.start('smtp.shopist.com', 587, 'shopist.com', 'noreply@shopist.com', 'Sh0p1st$M@il2024!', :plain) do |smtp|
    smtp.send_message(message, 'noreply@shopist.com', to_email)
  end
end

# VULN 3: Hardcoded admin credentials in login check - bypass with known password
def authenticate_admin(username, password)
  if username == "shopist_admin" && password == "Adm1n$Sh0p1st#2024"
    { success: true, role: "admin" }
  else
    { success: false }
  end
end
