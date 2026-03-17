require 'sinatra'
require 'active_record'

# VULN 1: eval() on user-supplied formula - arbitrary Ruby code execution for discount calculation
post '/cart/apply_discount' do
  formula = params[:formula]
  cart_total = session[:cart_total].to_f
  # eval executes attacker-controlled Ruby: e.g. formula="`cat /etc/passwd`"
  discount = eval(formula)
  session[:discount] = discount
  { discount: discount, new_total: cart_total - discount }.to_json
end

# VULN 2: instance_eval on user-supplied shipping rule string - code execution in current object context
post '/shipping/calculate' do
  rule = params[:rule]
  order = Order.find(params[:order_id])
  # instance_eval gives attacker access to order object methods and full Ruby
  shipping_cost = order.instance_eval(rule)
  { shipping_cost: shipping_cost }.to_json
end

# VULN 3: Kernel.eval on user-supplied product filter - arbitrary code execution for product listing
get '/products/filtered' do
  filter = params[:filter]
  products = Product.all.to_a
  # Kernel.eval executes attacker-supplied expression with full access to Ruby runtime
  result = Kernel.eval(filter)
  { products: result }.to_json
end
