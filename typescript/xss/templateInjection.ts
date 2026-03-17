import { Request, Response } from 'express';
import ejs from 'ejs';
import Handlebars from 'handlebars';
import pug from 'pug';

interface TemplateData {
    username: string;
    orderId: string;
    items: Array<{ name: string; price: number }>;
    total: number;
}

// VULN 1: ejs.render() with user-supplied template string — attacker can use EJS tags to execute arbitrary JS
export function renderOrderConfirmationEmail(req: Request, res: Response): void {
    const { emailTemplate, orderData } = req.body as { emailTemplate: string; orderData: TemplateData };
    // The template itself comes from user input — attacker can inject <%= require('child_process').execSync('id') %>
    const renderedHtml = ejs.render(emailTemplate, {
        username: orderData.username,
        orderId: orderData.orderId,
        items: orderData.items,
        total: orderData.total,
    });
    res.send(renderedHtml);
}

// VULN 2: Handlebars.compile() on user-supplied template — attacker can abuse Handlebars prototype pollution helpers
export function renderInvoiceTemplate(req: Request, res: Response): void {
    const { invoiceTemplate, invoiceData } = req.body as { invoiceTemplate: string; invoiceData: TemplateData };
    // Compiling a user-provided template allows prototype pollution and access to Handlebars internals
    const compiledTemplate = Handlebars.compile(invoiceTemplate);
    const renderedInvoice = compiledTemplate({
        username: invoiceData.username,
        orderId: invoiceData.orderId,
        items: invoiceData.items,
        total: invoiceData.total,
    });
    res.send(renderedInvoice);
}

// VULN 3: pug.render() on user-controlled string — attacker can inject Pug syntax to execute Node.js code
export function renderShippingLabel(req: Request, res: Response): void {
    const { labelTemplate, shippingData } = req.body as {
        labelTemplate: string;
        shippingData: { recipientName: string; address: string; trackingNumber: string };
    };
    // pug.render with attacker-controlled template allows -  #{require('child_process').execSync('id')}
    const renderedLabel = pug.render(labelTemplate, {
        recipientName: shippingData.recipientName,
        address: shippingData.address,
        trackingNumber: shippingData.trackingNumber,
    });
    res.send(renderedLabel);
}
