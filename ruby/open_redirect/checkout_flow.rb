require 'sinatra'

# VULN 1: Unvalidated params[:next] used in redirect_to after login - open redirect to phishing site
post '/login' do
  username = params[:username]
  password = params[:password]
  user = User.find_by(username: username)
  if user&.authenticate(password)
    session[:user_id] = user.id
    redirect params[:next]
  else
    halt 401, 'Invalid credentials'
  end
end

# VULN 2: Unvalidated params[:return_url] after checkout complete - redirects to attacker-controlled URL
post '/checkout/complete' do
  order_id = params[:order_id]
  return_url = params[:return_url]
  Order.find(order_id).update(status: 'paid')
  session[:cart] = nil
  redirect return_url
end

# VULN 3: OAuth state param used directly as redirect destination - CSRF token repurposed as open redirect
get '/auth/callback' do
  code  = params[:code]
  state = params[:state]
  token = exchange_oauth_code(code)
  session[:oauth_token] = token
  redirect params[:state]
end
