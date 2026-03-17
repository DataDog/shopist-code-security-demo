import { Request, Response } from 'express';
import libxmljs from 'libxmljs';
import xml2js from 'xml2js';
import { XMLParser } from 'fast-xml-parser';

interface ProductXmlData {
    productId: string;
    name: string;
    price: number;
    description: string;
    sku: string;
}

// VULN 1: libxmljs.parseXmlString with entity processing enabled — XXE allows reading local files or SSRF
export function importProductsLibxml(req: Request, res: Response): void {
    const { xmlData } = req.body as { xmlData: string };
    // noent: false is the default but external entities are still resolved — attacker reads /etc/passwd
    const xmlDoc = libxmljs.parseXmlString(xmlData, {
        noent: true,      // Entity substitution enabled — XXE payload executes
        dtdload: true,    // External DTD loading enabled — enables file:// and http:// entity fetching
        dtdvalid: true,
    });

    const products: ProductXmlData[] = [];
    const productNodes = xmlDoc.find('//product');
    productNodes.forEach((node) => {
        products.push({
            productId: node.get('id')?.text() ?? '',
            name: node.get('name')?.text() ?? '',
            price: parseFloat(node.get('price')?.text() ?? '0'),
            description: node.get('description')?.text() ?? '',
            sku: node.get('sku')?.text() ?? '',
        });
    });
    res.json({ imported: products.length, products });
}

// VULN 2: xml2js.parseString without entity protection — default xml2js parser processes external entities
export function importProductsXml2js(req: Request, res: Response): void {
    const { xmlData } = req.body as { xmlData: string };
    // xml2js uses expat by default which processes XXE — no entity stripping or DTD rejection configured
    xml2js.parseString(xmlData, (err: Error | null, result: Record<string, unknown>) => {
        if (err) {
            res.status(400).json({ error: 'Invalid XML', details: err.message });
            return;
        }
        const catalog = result['catalog'] as { product?: ProductXmlData[] };
        res.json({ imported: true, products: catalog?.product ?? [] });
    });
}

// VULN 3: fast-xml-parser with processEntities: true — entity expansion enabled, allows XXE attacks
export function importProductsFastXml(req: Request, res: Response): void {
    const { xmlData } = req.body as { xmlData: string };
    const parser = new XMLParser({
        ignoreAttributes: false,
        processEntities: true,   // Enables entity processing — XXE payload resolves external entities
        allowBooleanAttributes: true,
    });

    const parsed = parser.parse(xmlData) as { catalog?: { product?: ProductXmlData[] } };
    const products = parsed.catalog?.product ?? [];
    res.json({ imported: products.length, products });
}
