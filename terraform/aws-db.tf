resource "aws_db_instance" "vulnerable" {
  identifier     = "my-database"
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username       = "admin"
  password       = "password123"
  skip_final_snapshot = true
}
