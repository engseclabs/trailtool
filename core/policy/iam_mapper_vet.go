//go:build vet

package policy

// loadDatasetMappings omits the generated IAM dataset during go vet.
func (m *IAMActionMapper) loadDatasetMappings() {}
