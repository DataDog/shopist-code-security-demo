package sqlinjection

// ListOrdersSorted returns an org's orders ordered by sortColumn.
//
// An ORDER BY target cannot be a bound query parameter, so sortColumn is
// concatenated into the SQL text. The org filter is passed as a bound
// parameter ($1).
func ListOrdersSorted(orgID int, sortColumn string) ([]Order, error) {
	query := "SELECT id, user_id, total, status FROM orders WHERE user_id = $1 ORDER BY " + sortColumn
	rows, err := db.Query(query, orgID)
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

// ListOrdersSorted backs the sorted order report endpoint.
