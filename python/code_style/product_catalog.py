# VULN 1: Class name uses snake_case instead of PascalCase
# Rule: python-code-style/class-name
# Python convention (PEP 8) requires class names to be PascalCase.
class product_catalog:
    def __init__(self):
        self.products = []


# VULN 2: Function name uses camelCase instead of snake_case
# Rule: python-code-style/function-naming
# Python convention (PEP 8) requires function names to be snake_case.
def getProductById(catalog, product_id):
    for product in catalog.products:
        if product["id"] == product_id:
            return product
    return None


# VULN 3: Method name uses camelCase inside a properly named class
# Rule: python-code-style/function-naming
class ShoppingCart:
    def __init__(self):
        self.items = []

    def addItem(self, item):
        self.items.append(item)

    def removeItem(self, item_id):
        self.items = [i for i in self.items if i["id"] != item_id]

    def calculateTotal(self):
        return sum(i["price"] for i in self.items)
