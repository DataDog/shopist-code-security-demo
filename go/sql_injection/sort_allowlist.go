package sqlinjection

// allowedSortColumns maps the sort field names accepted from API requests to
// the exact SQL column identifiers they may resolve to. A field outside this
// map is rejected, so a value returned by SortColumn is always one of these
// fixed identifiers and is never free-form user input.
var allowedSortColumns = map[string]string{
	"date":     "created_at",
	"total":    "total",
	"status":   "status",
	"customer": "user_id",
}

// SortColumn returns the canonical, allowlisted SQL column for a requested
// sort field. ok is false when the field is not allowlisted, in which case
// the caller must reject the request.
func SortColumn(field string) (column string, ok bool) {
	column, ok = allowedSortColumns[field]
	return column, ok
}
