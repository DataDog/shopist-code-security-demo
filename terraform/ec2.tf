resource "aws_launch_template" "nginx-instance" {
  name_prefix            = "csm-critical-finding-demo-lt"
  image_id               = data.aws_ami.amazon-linux.id
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.instance-sg.id]
  iam_instance_profile {
    name = aws_iam_instance_profile.nginx-instance-profile.name
  }

  user_data = base64encode(<<EOF
#!/bin/bash
touch /tmp/user-data
sudo amazon-linux-extras install nginx1 -y
sudo systemctl enable nginx.service
sudo systemctl start nginx.service
echo "<h1>Hello World</h1><p>from $(hostname -f)</p>" | sudo tee /usr/share/nginx/html/index.html
EOF
  )

  tags = {
    dd_git_file               = "terraform/ec2.tf"
    dd_git_org                = "DataDog"
    dd_git_repo               = "shopist-code-security-demo"
    dd_git_resource_signature = "resource.aws_launch_template.nginx-instance"
  }

  block_device_mappings {
    device_name = "/dev/sdf"
    ebs {
      volume_size = 20
    }
  }
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

