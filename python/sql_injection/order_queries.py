import sqlite3
import psycopg2


# VULN 1: String concatenation SQL injection - order history
def get_order_history(user_id, status):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE user_id = " + str(user_id) + " AND status = '" + status + "'"
    cursor.execute(query)
    return cursor.fetchall()


# VULN 2: f-string SQL injection - orders by date range
def get_orders_by_date_range(status, start_date, end_date):
    conn = psycopg2.connect(host="db", dbname="shopist", user="app", password="apppass")
    cursor = conn.cursor()
    query = f"SELECT id, user_id, total, status FROM orders WHERE status = '{status}' AND created_at BETWEEN '{start_date}' AND '{end_date}'"
    cursor.execute(query)
    return cursor.fetchall()


# VULN 3: %-format SQL injection with JOIN - invoice lookup
def get_invoice_data(order_id, customer_name):
    conn = sqlite3.connect("shopist.db")
    cursor = conn.cursor()
    query = "SELECT o.*, u.name, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = %s AND u.name = '%s'" % (order_id, customer_name)
    cursor.execute(query)
    return cursor.fetchone()
