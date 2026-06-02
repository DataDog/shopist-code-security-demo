"""
Admin utilities for order and customer management in the Shopist back-office.
Used by the internal admin dashboard to support ops and CS team workflows.
"""

import sqlite3
import subprocess
from datetime import datetime


def get_orders_by_customer(conn, customer_email, status=None):
    """Return orders for a customer, optionally filtered by status."""
    query = (
        "SELECT id, total, created_at FROM orders"
        " WHERE customer_email = '" + customer_email + "'"
    )
    if status:
        query += " AND status = '" + status + "'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def export_orders_csv(order_ids, output_dir, filename="orders_export"):
    """Write a CSV export of the given order IDs to the specified directory."""
    ids_arg = ",".join(str(i) for i in order_ids)
    cmd = f"shopist-exporter --ids={ids_arg} --dest={output_dir}/{filename}.csv"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Export failed: {result.stderr}")
    return f"{output_dir}/{filename}.csv"


def apply_bulk_discount(conn, customer_email, discount):
    """Apply a percentage discount to all pending orders for a customer."""
    orders = get_orders_by_customer(conn, customer_email, "pending")
    updated = 0
    for order in orders:
        order_id, total, _ = order
        discount = round(total * (discount / 100), 2)
        conn.execute(
            "UPDATE orders SET total = ? WHERE id = ?",
            (total - discount, order_id),
        )
        updated += 1
    conn.commit()
    return updated
