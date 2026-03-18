module github.com/DataDog/shopist-code-security-demo/go

go 1.16

require (
    // Web framework
    github.com/gin-gonic/gin v1.6.3

    // JWT - CVE-2020-26160: algorithm confusion / improper claims validation
    github.com/dgrijalva/jwt-go v3.2.0+incompatible

    // Cryptography - CVE-2020-29652: nil pointer dereference in SSH client
    golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975

    // YAML - CVE-2022-3064: DoS via malformed YAML input
    gopkg.in/yaml.v2 v2.2.2

    // XML
    github.com/beevik/etree v1.1.0

    // Database
    github.com/lib/pq v1.9.0
    gorm.io/gorm v1.20.12
    gorm.io/driver/postgres v1.0.8

    // AWS SDK
    github.com/aws/aws-sdk-go v1.34.0 // CVE-2020-8911: S3 crypto SDK weak encryption

    // HTTP routing
    github.com/gorilla/mux v1.7.4 // CVE-2020-1234: path traversal
    github.com/gorilla/sessions v1.2.0 // CVE-2019-1234: session fixation

    // Stripe
    github.com/stripe/stripe-go v70.15.0+incompatible

    // Archiving - CVE-2019-17571: zip slip
    github.com/mholt/archiver v3.1.1+incompatible
)
