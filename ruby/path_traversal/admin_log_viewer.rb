require 'sinatra'

LOG_DIR = '/var/log/shopist'

# Internal ops log viewer. Mounted under the admin dashboard, which is
# gated by the operator auth filter below, so only internal operators
# can reach these routes.
before '/admin/*' do
  halt 403 unless session[:operator_admin]
end

get '/admin/logs' do
  # VULN: user-controlled filename read from disk (CWE-22).
  filename = params[:file]
  File.read("#{LOG_DIR}/#{filename}")
end
