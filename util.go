package nradix

func zero[T any]() T {
	return *new(T)
}
