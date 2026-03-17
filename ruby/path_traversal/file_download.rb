require 'sinatra'

BASE_DIR = '/var/www/files'

# VULN 1: File.read with string concatenation - no path sanitization
get '/read' do
  filename = params[:file]
  path = BASE_DIR + '/' + filename
  File.read(path)
end

# VULN 2: send_file with user-controlled path - allows ../../etc/passwd
get '/download' do
  filename = params[:file]
  filepath = File.join(BASE_DIR, filename)
  send_file filepath
end

# VULN 3: File.open with string interpolation - stream arbitrary files
get '/export' do
  report_name = params[:name]
  full_path = File.join('/reports/output', report_name)
  File.open(full_path, 'rb', &:read)
end
