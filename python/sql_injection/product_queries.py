import sqlite3
import psycopg2


# VULN 1: String concatenation SQL injection - product search
def search_products(search_term):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT id, name, price, stock FROM products WHERE name LIKE '%" + search_term + "%' OR description LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()


# VULN 2: f-string SQL injection - price range filter
def get_products_by_price_range(min_price, max_price):
    conn = psycopg2.connect(host="db", dbname="shopist", user="app", password="apppass")
    cursor = conn.cursor()
    query = f"SELECT * FROM products WHERE price BETWEEN {min_price} AND {max_price} ORDER BY price ASC"
    cursor.execute(query)
    return cursor.fetchall()


# VULN 3: %-format SQL injection with ORDER BY - category filter
def get_products_by_category(category, sort_field):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE category = '%s' ORDER BY %s" % (category, sort_field)
    cursor.execute(query)
    return cursor.fetchall()
