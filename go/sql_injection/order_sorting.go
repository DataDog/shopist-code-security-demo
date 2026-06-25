package sqlinjection

// ListOrdersSorted returns an org's orders ordered by sortColumn.
//
// sortColumn is a SQL identifier, not a bound parameter. An ORDER BY target
// cannot be passed as a query placeholder, so the column name is concatenated
// into the query. The user-supplied sort field is resolved to an allowlisted
// column by SortColumn (see sort_allowlist.go) before it reaches this
// function, so sortColumn is always one of a fixed set of column names. The
// org filter still uses a bound parameter.
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
