package sqlinjection

import (
	"database/sql"
	"strconv"
)

// The patterns below concatenate a non-literal into a SQL string, which the
// string-concatenation rule flags. In each case the interpolated value cannot
// carry user-controlled text.

// defaultReportStatus is a compile-time constant, never user input.
const defaultReportStatus = "fulfilled"

// CountOrdersByDefaultStatus interpolates a constant status value.
func CountOrdersByDefaultStatus() (int, error) {
	query := "SELECT count(*) FROM orders WHERE status = '" + defaultReportStatus + "'"
	var n int
	err := db.QueryRow(query).Scan(&n)
	return n, err
}

// ListRecentOrders interpolates pageSize, an int rendered with strconv.Itoa,
// so only digits can reach the query.
func ListRecentOrders(pageSize int) (*sql.Rows, error) {
	query := "SELECT id, user_id, total FROM orders ORDER BY created_at DESC LIMIT " + strconv.Itoa(pageSize)
	return db.Query(query)
}

// ListProductsByName interpolates a sort direction resolved to a fixed ASC or
// DESC value, never the raw request string.
func ListProductsByName(direction string) (*sql.Rows, error) {
	dir := "ASC"
	if direction == "desc" {
		dir = "DESC"
	}
	query := "SELECT id, name, price FROM products ORDER BY name " + dir
	return db.Query(query)
}
