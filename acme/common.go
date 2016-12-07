package acme

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	ResourceNewNonce = Resource("new-nonce")
	ResourceNewReg   = Resource("new-reg")
)
