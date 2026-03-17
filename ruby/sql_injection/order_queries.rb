require 'active_record'
require 'pg'

# VULN 1: ActiveRecord string interpolation - order history
def get_order_history(user_id, status)
  Order.where("user_id = #{user_id} AND status = '#{status}'")
end

# VULN 2: String concatenation in pg query - orders by date range
def get_orders_by_date_range(status, start_date, end_date)
  conn = PG.connect(host: 'localhost', dbname: 'shopist')
  conn.exec(
    "SELECT * FROM orders WHERE status = '" + status +
    "' AND created_at BETWEEN '" + start_date + "' AND '" + end_date + "'"
  )
end

# VULN 3: find_by_sql with interpolation and JOIN - invoice lookup
def get_invoice_data(order_id, customer_name)
  Order.find_by_sql(
    "SELECT o.*, u.name, u.email FROM orders o " \
    "JOIN users u ON o.user_id = u.id " \
    "WHERE o.id = #{order_id} AND u.name = '#{customer_name}'"
  ).first
end
