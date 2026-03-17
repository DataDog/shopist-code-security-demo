import jakarta.servlet.http.*;
import javax.xml.parsers.*;
import javax.xml.stream.*;
import org.w3c.dom.*;
import java.io.*;

public class ProductImport extends HttpServlet {

    // VULN 1: DocumentBuilderFactory without disabling external entities (XXE)
    public Document parseProductCatalogXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(xmlInput);
    }

    // VULN 2: SAXParserFactory without disabling DTD processing (XXE via SAX)
    public void importProductsFromXml(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        parser.parse(req.getInputStream(), new org.xml.sax.helpers.DefaultHandler() {
            @Override
            public void startElement(String uri, String localName, String qName, org.xml.sax.Attributes attrs) {
                if ("product".equals(qName)) {
                    resp.setStatus(HttpServletResponse.SC_OK);
                }
            }
        });
    }

    // VULN 3: XMLInputFactory with IS_SUPPORTING_EXTERNAL_ENTITIES=true (XXE via StAX)
    public void streamParseInventoryFeed(InputStream xmlInput) throws XMLStreamException {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        XMLStreamReader reader = factory.createXMLStreamReader(xmlInput);
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                System.out.println("Element: " + reader.getLocalName());
            }
        }
    }
}
