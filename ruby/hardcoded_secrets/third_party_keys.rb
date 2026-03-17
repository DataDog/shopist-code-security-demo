require 'sendgrid-ruby'
require 'net/http'
require 'twilio-ruby'

# VULN 1: Hardcoded SendGrid API key - allows sending emails as Shopist domain
def send_shipping_notification(to_email, tracking_number)
  sg = SendGrid::API.new(api_key: 'SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB')
  data = {
    personalizations: [{ to: [{ email: to_email }] }],
    from: { email: 'shipping@shopist.com' },
    subject: "Your order has shipped! Tracking: #{tracking_number}",
    content: [{ type: 'text/plain', value: "Track your package at shopist.com/track/#{tracking_number}" }]
  }
  sg.client.mail._('send').post(request_body: data)
end

# VULN 2: Hardcoded Google Maps API key - allows unauthorized geocoding/billing
def geocode_shipping_address(address)
  api_key = "AIzaSyDaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567"
  uri = URI("https://maps.googleapis.com/maps/api/geocode/json?address=#{URI.encode_www_form_component(address)}&key=#{api_key}")
  response = Net::HTTP.get(uri)
  JSON.parse(response)
end

# VULN 3: Hardcoded Twilio account SID + auth token - allows sending SMS as Shopist
def send_sms_verification(phone_number, code)
  account_sid = 'AC1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p'
  auth_token  = '7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g'
  client = Twilio::REST::Client.new(account_sid, auth_token)
  client.messages.create(
    from: '+15551234567',
    to: phone_number,
    body: "Your Shopist verification code is: #{code}"
  )
end
