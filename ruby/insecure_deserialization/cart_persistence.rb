require 'sinatra'
require 'base64'

# VULN 1: Marshal.load on user-controlled cookie - arbitrary RCE via deserialization gadget
get '/cart' do
  cart_cookie = request.cookies['cart_data']
  cart = Marshal.load(Base64.decode64(cart_cookie))
  erb :cart, locals: { cart: cart }
end

# VULN 2: Marshal.load on raw request body - RCE when client sends crafted binary payload
post '/cart/restore' do
  cart = Marshal.load(request.body.read)
  session[:cart] = cart
  { status: 'restored', item_count: cart.items.length }.to_json
end

# VULN 3: Marshal.load on uploaded file contents - RCE via malicious cart export file
post '/cart/import' do
  uploaded_file = params[:cart_file][:tempfile]
  cart = Marshal.load(uploaded_file.read)
  session[:cart] = cart
  redirect '/cart'
end
