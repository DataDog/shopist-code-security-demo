import { Request, Response } from 'express';
import axios from 'axios';
import http from 'http';

interface ProductData {
    productId: string;
    title: string;
    description: string;
    price: number;
}

// VULN 1: User-supplied source URL passed directly to http.get — SSRF allows scanning internal network
export function fetchProductDataFromSource(req: Request, res: Response): void {
    const { sourceUrl } = req.query as { sourceUrl: string };
    // No URL validation — attacker can target internal services, metadata endpoints, or file:// URIs
    http.get(sourceUrl, (response) => {
        let data = '';
        response.on('data', (chunk: string) => { data += chunk; });
        response.on('end', () => {
            try {
                const productData: ProductData = JSON.parse(data);
                res.json({ enriched: true, product: productData });
            } catch {
                res.status(400).json({ error: 'Invalid product data format' });
            }
        });
    }).on('error', (err: Error) => {
        res.status(500).json({ error: err.message });
    });
}

// VULN 2: User-supplied RSS feed URL fetched via axios.get — no allowlist, internal hosts reachable
export async function importProductFeed(req: Request, res: Response): Promise<void> {
    const { feedUrl, sellerId } = req.body as { feedUrl: string; sellerId: string };
    // Merchant-supplied feedUrl is fetched without validation — SSRF to internal infrastructure
    const feedResponse = await axios.get(feedUrl, {
        headers: { 'User-Agent': 'Shopist-ProductImporter/1.0' },
        timeout: 10000,
    });
    const feedContent = feedResponse.data as string;
    res.json({ sellerId, itemCount: feedContent.length, preview: feedContent.substring(0, 200) });
}

// VULN 3: User-controlled API base URL string-concatenated then fetched — attacker redirects requests
export async function syncInventoryFromPartner(req: Request, res: Response): Promise<void> {
    const { apiBaseUrl, partnerId, apiKey } = req.body as {
        apiBaseUrl: string;
        partnerId: string;
        apiKey: string;
    };
    // apiBaseUrl is fully attacker-controlled; concatenation allows path injection and SSRF
    const inventoryEndpoint = apiBaseUrl + '/inventory/' + partnerId;
    const response = await axios.get(inventoryEndpoint, {
        headers: { Authorization: `Bearer ${apiKey}` },
    });
    res.json({ inventory: response.data });
}
