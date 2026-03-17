const express = require('express');
const vm = require('vm');

const router = express.Router();

// VULN 1: eval() on user-supplied discount formula - arbitrary code execution
router.post('/promotions/apply', (req, res) => {
    const { formula, cartTotal, itemCount } = req.body;
    // formula is user-controlled: e.g. "require('child_process').execSync('id').toString()"
    const discount = eval(formula);
    const finalTotal = cartTotal - discount;
    res.json({ originalTotal: cartTotal, discount, finalTotal });
});

router.get('/promotions/preview', (req, res) => {
    const { formula, sampleTotal } = req.query;
    const previewDiscount = eval(formula);
    res.json({ sampleTotal, previewDiscount, result: sampleTotal - previewDiscount });
});

// VULN 2: vm.runInNewContext() with user-supplied code - sandbox escape RCE
router.post('/shipping/calculate', (req, res) => {
    const { code, orderWeight, destination } = req.body;
    const sandbox = {
        weight: orderWeight,
        destination: destination,
        baseRate: 5.99,
        result: 0,
    };
    // vm module sandbox is not a security boundary - attacker can escape via prototype chain
    vm.runInNewContext(code, sandbox);
    res.json({ weight: orderWeight, destination, shippingCost: sandbox.result });
});

// VULN 3: new Function() on user-supplied shipping rule string - arbitrary code execution
router.post('/shipping/rules/test', (req, res) => {
    const { userCode, weight, zipCode } = req.body;
    // new Function executes in global scope - allows access to process, require, etc.
    const shippingRule = new Function('weight', 'zipCode', userCode);
    const shippingCost = shippingRule(weight, zipCode);
    res.json({ weight, zipCode, shippingCost });
});

module.exports = router;
