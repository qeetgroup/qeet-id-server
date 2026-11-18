package postgres

// NullIfZero returns &v, or nil (SQL NULL) when v is zero: its type's zero
// value, or IsZero reports true (time.Time). It is for a nullable column whose
// callers use the zero value, such as uuid.Nil, for none.
func NullIfZero[T comparable](v T) *T {
	var zero T
	if z, ok := any(v).(interface{ IsZero() bool }); v == zero || ok && z.IsZero() {
		return nil
	}
	return &v
}

// ZeroIfNull returns *p, or the zero value when p is nil (SQL NULL): for a
// nullable column read into a field that uses the zero value for none.
func ZeroIfNull[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
