require 'sinatra'
require 'active_record'

# VULN 1: Reflected XSS - unsanitized search query rendered as raw HTML in response
get '/products/search' do
  query = params[:q]
  results = Product.where("name LIKE ?", "%#{query}%")
  # raw HTML output: "<h1>Results for: #{params[:q]}</h1>" sent directly to browser
  content_type :html
  "<h1>Results for: #{params[:q]}</h1>" + results.map { |p| "<p>#{p.name}</p>" }.join
end

# VULN 2: Stored XSS - review text from DB rendered with raw() in ERB without escaping
get '/products/:id/reviews' do
  product = Product.find(params[:id])
  reviews = Review.where(product_id: product.id)
  # In ERB template: <%= raw(review.text) %> — stored script executes in every visitor's browser
  erb :product_reviews, locals: { product: product, reviews: reviews }
end

# VULN 3: XSS in error message - unsanitized username reflected as raw HTML in login failure response
post '/login' do
  username = params[:username]
  password = params[:password]
  user = User.find_by(username: username)
  unless user&.authenticate(password)
    content_type :html
    halt 401, "<p>Login failed for: #{params[:username]}</p>"
  end
  session[:user_id] = user.id
  redirect '/dashboard'
end
