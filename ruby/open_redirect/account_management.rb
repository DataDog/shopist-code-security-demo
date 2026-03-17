require 'sinatra'

# VULN 1: Unvalidated params[:redirect_to] in password reset confirm - redirects to attacker after reset
post '/password/reset/confirm' do
  token       = params[:token]
  new_password = params[:password]
  redirect_to  = params[:redirect_to]
  user = User.find_by(reset_token: token)
  if user && user.reset_token_expires_at > Time.now
    user.update(password: new_password, reset_token: nil)
    redirect redirect_to
  else
    halt 400, 'Invalid or expired token'
  end
end

# VULN 2: request.referer used directly in logout redirect - attacker sets Referer header to phishing URL
post '/logout' do
  session.clear
  referer = request.referer
  redirect referer || '/'
end

# VULN 3: Unvalidated params[:callback_url] for social account linking - redirects to attacker after OAuth
get '/account/social/link/callback' do
  provider     = params[:provider]
  uid          = params[:uid]
  callback_url = params[:callback_url]
  current_user.social_accounts.create(provider: provider, uid: uid)
  redirect callback_url
end
