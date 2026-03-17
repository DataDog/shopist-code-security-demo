import sqlite3
import psycopg2


# VULN 1: String concatenation SQL injection - login
def authenticate_user(username, password):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()


# VULN 2: f-string SQL injection - profile lookup
def get_user_profile(user_id):
    conn = psycopg2.connect(host="db", dbname="shopist", user="app", password="apppass")
    cursor = conn.cursor()
    query = f"SELECT id, name, email, role FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


# VULN 3: %-format SQL injection - admin user search
def search_users_admin(search_term):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT id, username, email, role FROM users WHERE username LIKE '%%%s%%' OR email LIKE '%%%s%%'" % (search_term, search_term)
    cursor.execute(query)
    return cursor.fetchall()
