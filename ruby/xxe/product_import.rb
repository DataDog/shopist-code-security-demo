require 'sinatra'
require 'nokogiri'
require 'rexml/document'

# VULN 1: Nokogiri::XML with default options - external entity expansion enabled in older Nokogiri, allows XXE/file read
post '/products/import/xml' do
  xml_string = request.body.read
  doc = Nokogiri::XML(xml_string)
  products = doc.xpath('//product').map do |node|
    { name: node.at('name')&.text, price: node.at('price')&.text, sku: node.at('sku')&.text }
  end
  products.each { |p| Product.create(p) }
  { imported: products.length }.to_json
end

# VULN 2: REXML::Document.new without entity expansion disabled - XXE via crafted DOCTYPE/ENTITY
post '/products/import/rexml' do
  xml_string = request.body.read
  doc = REXML::Document.new(xml_string)
  products = []
  doc.elements.each('catalog/product') do |elem|
    products << {
      name:  elem.elements['name']&.text,
      price: elem.elements['price']&.text,
      sku:   elem.elements['sku']&.text
    }
  end
  products.each { |p| Product.create(p) }
  { imported: products.length }.to_json
end

# VULN 3: LibXML::XML::Document.string with entity loading - external entity injection via network or file
post '/products/import/libxml' do
  xml_string = request.body.read
  doc = LibXML::XML::Document.string(xml_string)
  products = doc.find('//product').map do |node|
    { name: node.find_first('name')&.content, price: node.find_first('price')&.content }
  end
  products.each { |p| Product.create(p) }
  { imported: products.length }.to_json
end
