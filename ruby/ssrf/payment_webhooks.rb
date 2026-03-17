require 'sinatra'
require 'net/http'
require 'open-uri'
require 'json'

# VULN 1: User-controlled webhook URL posted to directly - SSRF to internal services or cloud metadata
post '/webhooks/register' do
  webhook_url = params[:webhook_url]
  payload = { event: 'order.created', order_id: params[:order_id] }.to_json
  Net::HTTP.post(URI(webhook_url), payload, 'Content-Type' => 'application/json')
  { registered: true }.to_json
end

# VULN 2: User-supplied product image URL fetched via open() - SSRF via open-uri, allows reading internal URLs
post '/products/upload_image' do
  image_url = params[:image_url]
  image_data = open(image_url).read
  filename = "product_#{params[:product_id]}.jpg"
  File.write("/var/www/images/#{filename}", image_data)
  { saved: filename }.to_json
end

# VULN 3: User-controlled carrier tracking URL fetched via URI.open - SSRF to arbitrary hosts
get '/orders/track' do
  carrier_url = params[:carrier_url]
  tracking_data = URI.open(carrier_url).read
  JSON.parse(tracking_data).to_json
end
