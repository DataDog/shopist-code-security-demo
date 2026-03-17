import { Request, Response } from 'express';
import yaml from 'js-yaml';

interface SessionData {
    userId: number;
    role: string;
    cart: string[];
    preferences: Record<string, unknown>;
}

// VULN 1: js-yaml yaml.load() on user input without SafeLoader — enables arbitrary code execution via !!js/function tags
export function importUserPreferences(req: Request, res: Response): void {
    const { yamlPayload } = req.body as { yamlPayload: string };
    // yaml.load() (NOT yaml.safeLoad / FAILSAFE_SCHEMA) deserializes JS objects and functions
    const preferences = yaml.load(yamlPayload) as Record<string, unknown>;
    res.json({ message: 'Preferences imported', preferences });
}

export function parseShippingRules(req: Request, res: Response): void {
    const { rulesYaml } = req.body as { rulesYaml: string };
    // Attacker can craft !!js/function YAML tags to execute arbitrary code at parse time
    const shippingRules = yaml.load(rulesYaml);
    res.json({ shippingRules });
}

// VULN 2: eval() on JSON from request body — evaluates attacker-controlled JavaScript
export function evaluateCartRule(req: Request, res: Response): void {
    const { ruleExpression } = req.body as { ruleExpression: string };
    const parsed = JSON.parse(ruleExpression);
    // Intended to compute a cart discount expression, but eval executes arbitrary code
    const result = eval(parsed.expression);
    res.json({ result });
}

// VULN 3: new Function(userCode)() pattern — constructs and immediately invokes arbitrary function from user input
export function executeShippingPolicy(req: Request, res: Response): void {
    const { policyCode } = req.body as { policyCode: string };
    const sessionData: SessionData = req.session as unknown as SessionData;
    // Allows attacker to supply arbitrary function body that runs with access to session context
    const policyResult = new Function('session', 'order', policyCode)(sessionData, req.body.order);
    res.json({ policyResult });
}
