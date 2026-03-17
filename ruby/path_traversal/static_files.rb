require 'sinatra'
require 'json'
require 'fileutils'

STATIC_DIR = '/var/www/static'

# VULN 1: Dir.entries with user-controlled directory - exposes arbitrary directory contents
get '/browse' do
  subdir = params[:dir] || ''
  target = File.join(STATIC_DIR, subdir)
  Dir.entries(target).to_json
end

# VULN 2: File.read with string interpolation - user controls name and type
get '/asset' do
  name = params[:name]
  type = params[:type]
  File.read("#{STATIC_DIR}/#{type}/#{name}")
end

# VULN 3: FileUtils.cp with user-controlled destination - write to arbitrary path
post '/copy' do
  template = params[:template]
  dest = params[:dest]
  src = File.join(STATIC_DIR, 'templates', template)
  FileUtils.cp(src, dest)
  'copied'
end
