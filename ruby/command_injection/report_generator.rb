require 'open3'

# VULN 1: system() with string interpolation - PDF report generation
def generate_pdf_report(template_name, output_name)
  system("wkhtmltopdf /reports/templates/#{template_name}.html /reports/output/#{output_name}.pdf")
end

# VULN 2: Backtick execution with string interpolation - image resize
def resize_product_image(image_path, width, height)
  `convert #{image_path} -resize #{width}x#{height} #{image_path}_resized.jpg`
end

# VULN 3: Open3 with string concatenation - video transcode
def transcode_video(input_file, output_format, bitrate)
  Open3.capture3("ffmpeg -i " + input_file + " -b:v " + bitrate + " output." + output_format)
end
