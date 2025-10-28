import requests


def get_product_from_api(product_id):
    try:
        r = requests.get(f"https://api.provider.ext/products/{product_id}")
        return r.json()
    except requests.exceptions.RequestException as e:
        print(e)
    return None
