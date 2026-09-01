resource "aws_instance" "example" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  metadata_options {
    http_tokens = "required"
  }
  disable_api_termination = true
  tags = {
    Name = "test-instance"
  }
}
