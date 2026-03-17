import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import org.w3c.dom.Document
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import javax.xml.stream.XMLInputFactory

@RestController
class ProductImport {

    // VULN 1: DocumentBuilderFactory without disabling external entities - product catalog XML import
    @PostMapping("/api/catalog/import-xml")
    fun importProductCatalog(@RequestBody xmlContent: String): Map<String, Any> {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val doc: Document = builder.parse(InputSource(StringReader(xmlContent)))
        doc.documentElement.normalize()
        val products = doc.getElementsByTagName("product")
        return mapOf("status" to "imported", "productCount" to products.length)
    }

    // VULN 2: SAXParserFactory without disabling DTD - product feed ingestion
    @PostMapping("/api/catalog/ingest-feed")
    fun ingestProductFeed(@RequestBody xmlFeed: String): Map<String, Any> {
        val factory = SAXParserFactory.newInstance()
        val parser = factory.newSAXParser()
        val itemsFound = mutableListOf<String>()
        val handler = object : org.xml.sax.helpers.DefaultHandler() {
            override fun startElement(uri: String, localName: String, qName: String, attributes: org.xml.sax.Attributes) {
                if (qName == "item") {
                    itemsFound.add(attributes.getValue("id") ?: "unknown")
                }
            }
        }
        parser.parse(InputSource(StringReader(xmlFeed)), handler)
        return mapOf("status" to "ingested", "items" to itemsFound)
    }

    // VULN 3: XMLInputFactory with IS_SUPPORTING_EXTERNAL_ENTITIES = true - supplier data import
    @PostMapping("/api/suppliers/import")
    fun importSupplierData(@RequestBody xmlData: String): Map<String, Any> {
        val factory = XMLInputFactory.newInstance()
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true)
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true)
        val reader = factory.createXMLStreamReader(StringReader(xmlData))
        val elements = mutableListOf<String>()
        while (reader.hasNext()) {
            val event = reader.next()
            if (event == javax.xml.stream.XMLStreamConstants.START_ELEMENT) {
                elements.add(reader.localName)
            }
        }
        reader.close()
        return mapOf("status" to "imported", "elements" to elements)
    }
}
