require 'sinatra'
require 'yaml'
require 'base64'
require 'json'

# VULN 1: YAML.load on user input - executes arbitrary Ruby objects via Psych deserialization (RCE in Ruby < 3.1)
post '/session/restore' do
  user_prefs = params[:preferences]
  preferences = YAML.load(user_prefs)
  session[:user_preferences] = preferences
  { status: 'ok' }.to_json
end

# VULN 2: eval() on JSON string from user input - arbitrary code execution
post '/session/apply_discount' do
  discount_rule = params[:rule]
  json_string = request.body.read
  result = eval(json_string)
  session[:discount] = result[:discount_pct]
  { applied: true }.to_json
end

# VULN 3: Marshal.load on base64-decoded session param - RCE via crafted session payload
get '/session/load' do
  session_param = params[:session_data]
  session_obj = Marshal.load(Base64.decode64(session_param))
  session[:user_id]   = session_obj[:user_id]
  session[:cart_id]   = session_obj[:cart_id]
  session[:role]      = session_obj[:role]
  redirect '/dashboard'
end
