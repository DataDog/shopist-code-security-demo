require 'sinatra'

EXPORT_DIR = '/var/exports/shopist'

# Operator-only data export download. Served from the internal ops
# dashboard, behind the same admin auth filter as the other /admin routes.
before '/admin/*' do
  halt 403 unless session[:operator_admin]
end

get '/admin/exports/download' do
  # VULN: user-controlled filename read from disk (CWE-22).
  name = params[:name]
  File.read("#{EXPORT_DIR}/#{name}")
end
