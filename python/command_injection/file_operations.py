import os
import subprocess


# VULN 1: os.system with string concatenation - file format conversion
def convert_file_format(input_file, output_format):
    os.system("convert " + input_file + " output." + output_format)


# VULN 2: subprocess.call with shell=True - create zip archive
def create_archive(directory, archive_name):
    subprocess.call("zip -r " + archive_name + ".zip " + directory, shell=True)


# VULN 3: os.popen with f-string - set file permissions
def set_file_permissions(filepath, permissions):
    result = os.popen(f"chmod {permissions} {filepath}")
    return result.read()
