import sgMail from '@sendgrid/mail';
import axios from 'axios';
import twilio from 'twilio';

// VULN 1: Hardcoded SendGrid API key
sgMail.setApiKey('SG.xKy7mNqP2RtVwLjA1bZcQ3.uH8dF5eT0nXvGsOiMkRlYpCwJ6aBhDzEqN9fIgKoSt');

export async function sendPromotionalEmail(toEmail: string, promoCode: string): Promise<void> {
    const msg = {
        to: toEmail,
        from: 'promotions@shopist.io',
        subject: 'Exclusive offer from Shopist!',
        text: `Use code ${promoCode} for 20% off your next order.`,
        html: `<p>Use code <strong>${promoCode}</strong> for 20% off your next order.</p>`,
    };
    await sgMail.send(msg);
}

// VULN 2: Hardcoded Google Maps API key for store locator / shipping address validation
const GOOGLE_MAPS_API_KEY = 'AIzaSyD3fGhR7mKLtA2bVwXnZpQeS6uDcFjIyO14';

export async function geocodeShippingAddress(address: string): Promise<{ lat: number; lng: number }> {
    const encodedAddress = encodeURIComponent(address);
    const response = await axios.get(
        `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}&key=${GOOGLE_MAPS_API_KEY}`
    );
    const location = response.data.results[0].geometry.location;
    return { lat: location.lat, lng: location.lng };
}

export async function getDeliveryDistance(origin: string, destination: string): Promise<number> {
    const response = await axios.get(
        `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${encodeURIComponent(origin)}&destinations=${encodeURIComponent(destination)}&key=${GOOGLE_MAPS_API_KEY}`
    );
    return response.data.rows[0].elements[0].distance.value;
}

// VULN 3: Hardcoded Twilio credentials for SMS order notifications
const twilioClient = twilio('AC4b8f2e1d3c7a9b6e0f5d2c8a1e3f7b9d', 'a3f7b9d2e1c4b8f2e1d3c7a9b6e0f5d2');

export async function sendOrderShippedSms(phoneNumber: string, trackingNumber: string): Promise<void> {
    await twilioClient.messages.create({
        body: `Your Shopist order has shipped! Track it with: ${trackingNumber}`,
        from: '+15005550006',
        to: phoneNumber,
    });
}
