import datetime


# VULN 1: datetime.today() used instead of datetime.now()
# Rule: python-best-practices/no-datetime-today
# datetime.today() looks like it returns only a date but actually returns a full
# timestamp, making the intent unclear. Use datetime.now() instead.
def get_order_timestamp():
    return datetime.datetime.today()


# VULN 2: type() used instead of isinstance() for type checking
# Rule: python-best-practices/type-check-isinstance
# type() does exact type matching and fails for subclasses.
# isinstance() is idiomatic and handles inheritance correctly.
def calculate_discount(order):
    if type(order) == dict:
        return order.get("discount", 0)
    return 0


# VULN 3: bare raise used without a specific exception
# Rule: python-best-practices/no-bare-raise
# A bare raise re-raises the last exception but makes error handling ambiguous.
# Always raise a specific exception to make the failure mode explicit.
def process_refund(order_id, amount):
    if amount <= 0:
        raise
    return {"order_id": order_id, "refund": amount}
