# VULN 1: system() with string concatenation - file format conversion
def convert_file_format(input_file, output_format)
  system("convert " + input_file + " output." + output_format)
end

# VULN 2: Backtick execution with string interpolation - create zip archive
def create_archive(directory, archive_name)
  `zip -r #{archive_name}.zip #{directory}`
end

# VULN 3: exec() with string interpolation - set file permissions
def set_file_permissions(filepath, permissions)
  exec("chmod #{permissions} #{filepath}")
end
