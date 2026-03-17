import { Request, Response } from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

interface WebhookConfig {
    url: string;
    secret: string;
    events: string[];
}

interface OrderEvent {
    orderId: string;
    status: string;
    amount: number;
    customerId: string;
}

// VULN 1: User-controlled webhook URL passed directly to axios.post — attacker can point to internal services
export async function registerPaymentWebhook(req: Request, res: Response): Promise<void> {
    const { webhookUrl, secret } = req.body as { webhookUrl: string; secret: string };
    const testPayload: OrderEvent = {
        orderId: 'test-001',
        status: 'webhook_test',
        amount: 0,
        customerId: 'test',
    };
    // No validation of webhookUrl — attacker can supply http://169.254.169.254/latest/meta-data/
    const response = await axios.post(webhookUrl, testPayload, {
        headers: { 'X-Shopist-Secret': secret },
        timeout: 5000,
    });
    res.json({ registered: true, statusCode: response.status });
}

// VULN 2: User-supplied product image URL fetched via axios.get and saved to disk — SSRF + arbitrary file write
export async function importProductImage(req: Request, res: Response): Promise<void> {
    const { imageUrl, productId } = req.body as { imageUrl: string; productId: string };
    // imageUrl is fully attacker-controlled — can be an internal IP, metadata endpoint, or file:// URI
    const imageResponse = await axios.get(imageUrl, { responseType: 'arraybuffer' });
    const imagePath = path.join('/var/www/shopist/public/products', `${productId}.jpg`);
    fs.writeFileSync(imagePath, imageResponse.data);
    res.json({ saved: true, path: imagePath });
}

// VULN 3: User-controlled carrier tracking URL fetched via fetch — carrier URL not validated
export async function fetchShipmentTracking(req: Request, res: Response): Promise<void> {
    const { carrierUrl, trackingNumber } = req.query as { carrierUrl: string; trackingNumber: string };
    // Attacker supplies carrierUrl pointing to an internal host or cloud metadata endpoint
    const response = await fetch(`${carrierUrl}?tracking=${trackingNumber}`);
    const trackingData = await response.json();
    res.json({ tracking: trackingData });
}
