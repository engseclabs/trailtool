// Shared timestamp helpers for the merge paths.
package dynamodb

func earliestNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || a < b {
		return a
	}
	return b
}

func latestNonEmpty(a, b string) string {
	if a > b {
		return a
	}
	return b
}
