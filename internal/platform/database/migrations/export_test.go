package migrations

// LockTimeout lets the external tests shorten how long a migration waits for
// a busy table.
var LockTimeout = &lockTimeout

// Source lets the external tests give the runner other migration files than
// the build's.
var Source = &source
