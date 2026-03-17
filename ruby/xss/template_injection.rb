require 'sinatra'
require 'erb'
require 'erubi'
require 'liquid'

# VULN 1: ERB template injection - user controls template string, gains full Ruby code execution
post '/products/custom_description' do
  user_template = params[:template]
  product = Product.find(params[:product_id])
  # ERB.new(user_template).result(binding) executes arbitrary Ruby if template is user-controlled
  rendered = ERB.new(user_template).result(binding)
  { description: rendered }.to_json
end

# VULN 2: Erubi rendering user input as template - arbitrary Ruby execution via <%= %> tags
post '/emails/preview' do
  email_template = params[:email_body]
  order = Order.find(params[:order_id])
  # Erubi::Engine compiles and evaluates the template, user can inject <%= `id` %>
  src = Erubi::Engine.new(email_template).src
  rendered = eval(src)
  { preview: rendered }.to_json
end

# VULN 3: Liquid template with user-controlled template string - object traversal and data exfiltration
post '/invoices/generate' do
  invoice_template = params[:template]
  order = Order.find(params[:order_id])
  # User-controlled Liquid template allows traversing exposed objects and leaking data
  template = Liquid::Template.parse(invoice_template)
  rendered = template.render('order' => order, 'user' => order.user, 'config' => Rails.application.config)
  { invoice: rendered }.to_json
end
