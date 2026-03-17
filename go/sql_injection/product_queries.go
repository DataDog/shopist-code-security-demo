package sqlinjection

import (
	"database/sql"
	"fmt"
)

// VULN 1: String concatenation SQL injection - product search
func SearchProducts(searchTerm string) ([]Product, error) {
	query := "SELECT id, name, price, stock FROM products WHERE name LIKE '%" +
		searchTerm + "%' OR description LIKE '%" + searchTerm + "%'"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.Stock)
		products = append(products, p)
	}
	return products, nil
}

// VULN 2: fmt.Sprintf SQL injection - price range filter
func GetProductsByPriceRange(minPrice, maxPrice string) ([]Product, error) {
	query := fmt.Sprintf(
		"SELECT * FROM products WHERE price BETWEEN %s AND %s ORDER BY price ASC",
		minPrice, maxPrice,
	)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price)
		products = append(products, p)
	}
	return products, nil
}

// VULN 3: String concatenation with ORDER BY injection - category filter
func GetProductsByCategory(category, sortField string) ([]Product, error) {
	query := "SELECT * FROM products WHERE category = '" + category + "' ORDER BY " + sortField
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.Category)
		products = append(products, p)
	}
	return products, nil
}

// Product placeholder to satisfy compiler
type Product struct {
	ID       int
	Name     string
	Price    float64
	Stock    int
	Category string
}

// User placeholder
type User struct {
	ID       int
	Username string
	Name     string
	Email    string
	Role     string
}

// db placeholder
var _ *sql.DB
