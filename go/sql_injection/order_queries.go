package sqlinjection

import (
	"fmt"
	"strconv"
)

// VULN 1: String concatenation SQL injection - order history
func GetOrderHistory(userID int, status string) ([]Order, error) {
	query := "SELECT * FROM orders WHERE user_id = " + strconv.Itoa(userID) + " AND status = '" + status + "'"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orders []Order
	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.UserID, &o.Total, &o.Status)
		orders = append(orders, o)
	}
	return orders, nil
}

// VULN 2: fmt.Sprintf SQL injection - orders by date range
func GetOrdersByDateRange(status, startDate, endDate string) ([]Order, error) {
	query := fmt.Sprintf(
		"SELECT id, user_id, total, status FROM orders WHERE status = '%s' AND created_at BETWEEN '%s' AND '%s'",
		status, startDate, endDate,
	)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orders []Order
	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.UserID, &o.Total, &o.Status)
		orders = append(orders, o)
	}
	return orders, nil
}

// VULN 3: String concatenation SQL injection with JOIN - invoice lookup
func GetInvoiceData(orderID, customerName string) (*Invoice, error) {
	query := "SELECT o.*, u.name, u.email FROM orders o JOIN users u ON o.user_id = u.id" +
		" WHERE o.id = " + orderID + " AND u.name = '" + customerName + "'"
	row := db.QueryRow(query)
	var inv Invoice
	err := row.Scan(&inv.OrderID, &inv.CustomerName, &inv.Email, &inv.Total)
	return &inv, err
}

type Order struct {
	ID     int
	UserID int
	Total  float64
	Status string
}

type Invoice struct {
	OrderID      int
	CustomerName string
	Email        string
	Total        float64
}
