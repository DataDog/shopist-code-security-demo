require 'sinatra'

INVOICE_DIR = '/var/www/invoices'

get '/invoices/download' do
  # Reduce to a bare filename so any directory or ../ components are
  # stripped before the read.
  name = File.basename(params[:file])
  # VULN (false positive): the scanner flags this interpolated read, but
  # `name` has already been reduced to a basename, so traversal is not
  # possible.
  File.read("#{INVOICE_DIR}/#{name}")
end
