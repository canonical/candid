package store

var (
	NewChecker    = newChecker
	StoreACLForOp = (*Store).aclForOp
)

const CheckersNamespace = checkersNamespace
