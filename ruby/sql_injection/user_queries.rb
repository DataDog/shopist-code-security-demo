require 'pg'
require 'sqlite3'

# VULN 1: String interpolation SQL injection - login
def authenticate_user(username, password)
  conn = PG.connect(host: 'localhost', dbname: 'shopist')
  result = conn.exec("SELECT * FROM users WHERE username = '#{username}' AND password = '#{password}'")
  result.first
end

# VULN 2: String concatenation SQL injection - profile lookup
def get_user_profile(user_id)
  db = SQLite3::Database.new('shopist.db')
  db.execute("SELECT id, name, email, role FROM users WHERE id = " + user_id.to_s).first
end

# VULN 3: ActiveRecord string interpolation in where - admin user search
def search_users_admin(search_term)
  User.where("username LIKE '%#{search_term}%' OR email LIKE '%#{search_term}%'")
end
