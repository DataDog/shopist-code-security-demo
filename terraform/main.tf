data "aws_availability_zones" "available_iac" {
  state = "available"
}

resource "aws_ebs_volume" "iac_volume" {
  availability_zone = data.aws_availability_zones.available_iac.names[0]
  size              = 1

  tags = {
    Name = "iac-scanning"
    Team = "demo"
  }
}
