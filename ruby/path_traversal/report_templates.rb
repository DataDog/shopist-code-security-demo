require 'sinatra'

TEMPLATE_DIR = '/var/www/report_templates'
ALLOWED_REPORTS = %w[sales inventory refunds tax].freeze

get '/reports/generate' do
  report = params[:report]
  # Only a fixed set of known report names is ever accepted.
  halt 400, 'Unknown report' unless ALLOWED_REPORTS.include?(report)
  # VULN (false positive): the scanner flags this read, but `report` is
  # constrained to the allowlist above, so it can never be an arbitrary
  # path.
  File.read("#{TEMPLATE_DIR}/#{report}.json")
end
