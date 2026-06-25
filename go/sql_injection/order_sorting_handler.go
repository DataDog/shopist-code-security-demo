package sqlinjection

import "fmt"

// BuildSortedOrderReport is the only caller of ListOrdersSorted. requestedSort
// is the raw sort field from an API request. It is resolved through the
// SortColumn allowlist, and any field that is not allowlisted is rejected
// here, so the value handed to ListOrdersSorted is never user-controlled text.
func BuildSortedOrderReport(orgID int, requestedSort string) ([]Order, error) {
	sortColumn, ok := SortColumn(requestedSort)
	if !ok {
		return nil, fmt.Errorf("unsupported sort field: %q", requestedSort)
	}
	return ListOrdersSorted(orgID, sortColumn)
}
