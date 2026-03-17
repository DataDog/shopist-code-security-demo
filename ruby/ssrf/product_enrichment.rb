require 'sinatra'
require 'net/http'
require 'open-uri'
require 'json'

# VULN 1: User-supplied source URL fetched via Net::HTTP.get - SSRF allows probing internal network
post '/products/import' do
  source_url = params[:source_url]
  product_data = Net::HTTP.get(URI(source_url))
  products = JSON.parse(product_data)
  products.each { |p| Product.create(p) }
  { imported: products.length }.to_json
end

# VULN 2: User-supplied RSS feed URL fetched via open() - SSRF through open-uri to internal services
get '/products/rss_import' do
  feed_url = params[:feed_url]
  feed_content = open(feed_url).read
  items = parse_rss_feed(feed_content)
  { items: items }.to_json
end

# VULN 3: User-controlled API base URL string-concatenated then fetched - SSRF to attacker-controlled host
get '/products/sync' do
  api_base = params[:api_base]
  endpoint = api_base + '/v1/products'
  uri = URI(endpoint)
  response = Net::HTTP.get_response(uri)
  JSON.parse(response.body).to_json
end
