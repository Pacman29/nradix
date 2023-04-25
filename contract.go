package nradix

type Tree[T comparable] interface {
	AddCIDR(cidr string, val T) error
	AddCIDRb(cidr []byte, val T) error
	SetCIDR(cidr string, val T) error
	SetCIDRb(cidr []byte, val T) error
	DeleteWholeRangeCIDR(cidr string) error
	DeleteWholeRangeCIDRb(cidr []byte) error
	DeleteCIDR(cidr string) error
	DeleteCIDRb(cidr []byte) error
	FindCIDR(cidr string) (T, error)
	FindCIDRb(cidr []byte) (T, error)
}
