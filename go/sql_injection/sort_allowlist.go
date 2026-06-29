package sqlinjection

// allowedSortColumns maps the sort field names accepted from API requests to
// the SQL column identifiers they resolve to.
var allowedSortColumns = map[string]string{
	"date":     "created_at",
	"total":    "total",
	"status":   "status",
	"customer": "user_id",
}

// SortColumn returns the SQL column mapped to a requested sort field. ok is
// false when the field is not in allowedSortColumns.
func SortColumn(field string) (column string, ok bool) {
	column, ok = allowedSortColumns[field]
	return column, ok
}
