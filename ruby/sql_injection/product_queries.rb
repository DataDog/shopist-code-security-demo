require 'active_record'

# VULN 1: ActiveRecord string interpolation in where - product search
def search_products(search_term)
  Product.where("name LIKE '%#{search_term}%' OR description LIKE '%#{search_term}%'")
end

# VULN 2: String concatenation in where - price range filter
def get_products_by_price_range(min_price, max_price)
  Product.where("price BETWEEN " + min_price.to_s + " AND " + max_price.to_s)
end

# VULN 3: find_by_sql with string interpolation and ORDER BY injection
def get_products_by_category(category, sort_field)
  Product.find_by_sql(
    "SELECT * FROM products WHERE category = '#{category}' ORDER BY #{sort_field}"
  )
end
