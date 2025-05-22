resource "aws_db_instance" "shopist_mysql_db_dev" {
  identifier          = "shopist-mysql-db"
  engine              = "mysql"
  instance_class      = "db.t2.micro"
  allocated_storage   = 10
  username            = "admin"
  password            = "password"
  publicly_accessible = false

  tags = {
    "dd_git_file"           = "terraform/db.tf"
    "dd_git_org"            = "DataDog"
    "dd_git_repo"           = "github.com/DataDog/shopist-code-security-demo"
    "dd_git_resource_lines" = "1:17"
    "dd_resource_signature" = "resource.aws_db_instance.shopist_mysql_db"
  }
}

resource "google_sql_database_instance" "bad_example" {
  name             = "bad-instance"
  database_version = "MYSQL_8"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-13312"
    database_flags {
      name  = "cross db ownership chaining"
      value = "on"
    }
  }
}
