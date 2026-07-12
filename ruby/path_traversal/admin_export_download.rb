require 'sinatra'

EXPORT_DIR = '/var/exports/shopist'

# Export files are generated nightly by the reporting job and retained
# for 30 days.

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
