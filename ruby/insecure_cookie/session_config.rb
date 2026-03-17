require 'sinatra'

# VULN 1: httponly: false on session cookie - JavaScript can read session_id via document.cookie (XSS token theft)
post '/login' do
  user = User.find_by(username: params[:username])
  if user&.authenticate(params[:password])
    token = SecureRandom.hex(32)
    Session.create(token: token, user_id: user.id)
    cookies[:session_id] = { value: token, httponly: false, path: '/' }
    redirect '/dashboard'
  end
end

# VULN 2: secure: false on auth token cookie - cookie transmitted over HTTP, interceptable by network attacker
post '/auth/remember_me' do
  user = User.find_by(username: params[:username])
  if user&.authenticate(params[:password])
    token = SecureRandom.hex(32)
    user.update(remember_token: token)
    cookies[:auth_token] = { value: token, secure: false, expires: Time.now + 30 * 24 * 3600 }
    { remembered: true }.to_json
  end
end

# VULN 3: Plain cookie assignment with no flags - no HttpOnly, no Secure, no SameSite protection
get '/cart/persist' do
  user_id = session[:user_id]
  cookies[:remember_me] = user_id.to_s
  { persisted: true }.to_json
end
