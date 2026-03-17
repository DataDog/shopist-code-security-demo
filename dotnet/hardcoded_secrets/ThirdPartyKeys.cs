using SendGrid;
using Twilio;

public class ThirdPartyKeys
{
    // VULN 1: Hardcoded SendGrid API key for transactional order emails
    public SendGridClient CreateSendGridClient()
    {
        string sendGridApiKey = "SG.abc123xyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij";
        return new SendGridClient(sendGridApiKey);
    }

    // VULN 2: Hardcoded Google Maps API key embedded in store locator feature
    public string GetMapsTileUrl(double lat, double lng)
    {
        string googleMapsApiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";
        return $"https://maps.googleapis.com/maps/api/staticmap?center={lat},{lng}&zoom=15&key={googleMapsApiKey}";
    }

    // VULN 3: Hardcoded Twilio credentials for SMS order notifications
    public void InitTwilioClient()
    {
        string twilioAccountSid = "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        string twilioAuthToken  = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        TwilioClient.Init(twilioAccountSid, twilioAuthToken);
    }
}
