const express = require('express');
const libxmljs = require('libxmljs');
const xml2js = require('xml2js');
const { XMLParser } = require('fast-xml-parser');

const router = express.Router();

// VULN 1: libxmljs.parseXmlString() with external entity processing enabled - XXE
router.post('/products/import/xml', (req, res) => {
    const { xmlData } = req.body;
    // noent: false (default) and dtdload: true allow external entity expansion
    const xmlDoc = libxmljs.parseXmlString(xmlData, {
        noent: false,
        dtdload: true,
        dtdvalid: true,
    });
    const products = xmlDoc.find('//product').map((node) => ({
        sku: node.get('sku') ? node.get('sku').text() : '',
        name: node.get('name') ? node.get('name').text() : '',
        price: node.get('price') ? parseFloat(node.get('price').text()) : 0,
    }));
    res.json({ imported: products.length, products });
});

// VULN 2: xml2js.parseString() with no entity protection - XXE via entity expansion
router.post('/catalog/import', (req, res) => {
    const { xmlData } = req.body;
    // xml2js with explicitArray does not strip external entities from DTD declarations
    xml2js.parseString(xmlData, { explicitArray: false, explicitRoot: false }, (err, result) => {
        if (err) return res.status(400).json({ error: err.message });
        const items = result.catalog ? result.catalog.item : [];
        const catalogItems = Array.isArray(items) ? items : [items];
        res.json({ imported: catalogItems.length, catalog: catalogItems });
    });
});

// VULN 3: fast-xml-parser with processEntities: true and external entity data - XXE
router.post('/inventory/sync', (req, res) => {
    const { xmlData } = req.body;
    const parser = new XMLParser({
        ignoreAttributes: false,
        processEntities: true,
        allowBooleanAttributes: true,
    });
    // processEntities: true allows external entity references to read local files
    const inventoryData = parser.parse(xmlData);
    const items = inventoryData.inventory ? inventoryData.inventory.item : [];
    const inventory = Array.isArray(items) ? items : [items];
    res.json({ synced: inventory.length, inventory });
});

module.exports = router;
