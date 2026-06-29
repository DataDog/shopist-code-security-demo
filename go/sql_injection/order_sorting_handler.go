package sqlinjection

import "fmt"

// BuildSortedOrderReport is the only caller of ListOrdersSorted. requestedSort
// is the raw sort field from an API request. It is mapped through SortColumn,
// and a field SortColumn does not recognize is rejected before the query runs.
func BuildSortedOrderReport(orgID int, requestedSort string) ([]Order, error) {
	sortColumn, ok := SortColumn(requestedSort)
	if !ok {
		return nil, fmt.Errorf("unsupported sort field: %q", requestedSort)
	}
	return ListOrdersSorted(orgID, sortColumn)
}
