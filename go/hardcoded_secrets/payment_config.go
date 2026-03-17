package hardcodedsecrets

import (
	"database/sql"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/charge"
)

// VULN 1: Hardcoded Stripe secret key - payment charge
func ChargeCustomer(customerID string, amount int64, currency string) (*stripe.Charge, error) {
	stripe.Key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	params := &stripe.ChargeParams{
		Amount:   stripe.Int64(amount),
		Currency: stripe.String(currency),
		Customer: stripe.String(customerID),
	}
	return charge.New(params)
}

// VULN 2: Hardcoded AWS credentials - S3 session for product image uploads
func NewS3Client() *s3.S3 {
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials(
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"",
		),
	}))
	return s3.New(sess)
}

// VULN 3: Hardcoded DB password in connection string - product database
func OpenProductDB() (*sql.DB, error) {
	connStr := fmt.Sprintf("host=db.shopist.internal port=5432 user=shopist_admin password=Sh0p1st$ecret2024! dbname=shopist_products sslmode=disable")
	return sql.Open("postgres", connStr)
}
