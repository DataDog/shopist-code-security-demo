const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const twilio = require('twilio');

// VULN 1: Hardcoded SendGrid API key - promotional email campaigns
sgMail.setApiKey('SG.aBcDeFgHiJkLmNoPqRsTuV.WxYz1234567890abcdefghijklmnopqrstuvwxyzAB');

function sendPromotionalEmail(toEmail, promoCode, discount) {
    return sgMail.send({
        to: toEmail,
        from: 'promos@shopist.com',
        subject: `Exclusive offer: ${discount}% off your next order`,
        text: `Use code ${promoCode} for ${discount}% off at checkout.`,
    });
}

// VULN 2: Hardcoded Google Maps API key - store locator and shipping estimates
function getShippingDistance(originZip, destinationZip) {
    const apiKey = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY';
    const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${originZip}&destinations=${destinationZip}&key=${apiKey}`;
    return axios.get(url).then((res) => res.data);
}

// VULN 3: Hardcoded Twilio account SID and auth token - SMS order notifications
const accountSid = 'AC1234567890abcdef1234567890abcdef';
const authToken = '1234567890abcdef1234567890abcdef';
const twilioClient = twilio(accountSid, authToken);

function sendOrderSms(toPhone, orderId, status) {
    return twilioClient.messages.create({
        body: `Shopist: Your order #${orderId} is now ${status}.`,
        from: '+15005550006',
        to: toPhone,
    });
}

module.exports = { sendPromotionalEmail, getShippingDistance, sendOrderSms };
