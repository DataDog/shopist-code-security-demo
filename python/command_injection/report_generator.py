import os
import subprocess


# VULN 1: os.system with f-string - PDF report generation
def generate_pdf_report(template_name, output_name):
    os.system(f"wkhtmltopdf /reports/templates/{template_name}.html /reports/output/{output_name}.pdf")


# VULN 2: subprocess.call with shell=True - image resize
def resize_product_image(image_path, width, height):
    subprocess.call(
        f"convert {image_path} -resize {width}x{height} {image_path}_resized.jpg",
        shell=True,
    )


# VULN 3: os.popen with string concatenation - video transcode
def transcode_video(input_file, output_format, bitrate):
    cmd = "ffmpeg -i " + input_file + " -b:v " + bitrate + " output." + output_format
    result = os.popen(cmd)
    return result.read()
