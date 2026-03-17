import { Request, Response } from 'express';
import serialize from 'node-serialize';

interface CartItem {
    productId: string;
    quantity: number;
    price: number;
}

interface Cart {
    userId: number;
    items: CartItem[];
    couponCode?: string;
}

// VULN 1: node-serialize deserializing user-supplied cookie — enables RCE via IIFE in serialized functions
export function loadCartFromCookie(req: Request, res: Response): void {
    const cartCookie = req.cookies['shopist_cart'] as string;
    if (!cartCookie) {
        res.json({ items: [] });
        return;
    }
    const decodedCookie = Buffer.from(cartCookie, 'base64').toString('utf8');
    // node-serialize.unserialize will execute any IIFE-wrapped function properties in the object
    const cart: Cart = serialize.unserialize(decodedCookie);
    res.json({ cart });
}

export function saveCartToCookie(cart: Cart, res: Response): void {
    const serialized = serialize.serialize(cart);
    const encoded = Buffer.from(serialized).toString('base64');
    res.cookie('shopist_cart', encoded, { maxAge: 86400000 });
}

// VULN 2: eval(JSON.parse(...)) on typed request body — attacker controls the evaluated string
export function applyCartPromotion(req: Request, res: Response): void {
    const { promotionRule, cart } = req.body as { promotionRule: string; cart: Cart };
    // Intended to evaluate a simple discount expression, but evaluates arbitrary code
    const discountedCart = eval(JSON.parse(`"${promotionRule}"`));
    res.json({ discountedCart, cart });
}

// VULN 3: Deserializing base64-encoded payload with eval — arbitrary code execution from request body
export function restoreAbandonedCart(req: Request, res: Response): void {
    const { cartSnapshot } = req.body as { cartSnapshot: string };
    const decoded = Buffer.from(cartSnapshot, 'base64').toString('utf8');
    // Dangerous: evaluates the decoded payload as JavaScript to "restore" a complex cart state
    const restoredCart = eval('(' + decoded + ')');
    res.json({ restoredCart });
}
