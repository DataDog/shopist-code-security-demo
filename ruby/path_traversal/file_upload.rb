require 'sinatra'
require 'zip'

UPLOAD_DIR = '/var/www/uploads'

# VULN 1: Write uploaded file to user-specified destination - arbitrary file write
post '/upload' do
  dest = params[:destination]
  uploaded = params[:file][:tempfile]
  save_path = File.join(UPLOAD_DIR, dest)
  File.write(save_path, uploaded.read)
  'uploaded'
end

# VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
post '/extract' do
  extract_to = params[:extract_to]
  archive_path = File.join(UPLOAD_DIR, params[:archive][:filename])
  Zip::File.open(archive_path) do |zip_file|
    zip_file.each do |entry|
      # zip slip: entry.name may contain ../ sequences
      dest_path = File.join(extract_to, entry.name)
      entry.extract(dest_path)
    end
  end
  'extracted'
end

# VULN 3: File.read with user-controlled filename - path traversal on read
get '/preview' do
  username = params[:user]
  filename = params[:file]
  path = UPLOAD_DIR + '/' + username + '/' + filename
  File.read(path)
end
