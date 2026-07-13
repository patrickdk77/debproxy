package server

// TestValkeyAddr is set by the external test package's TestMain (see
// valkey_test.go's TestMain) so internal (package server) test files can
// also reach the one shared test Valkey container -- Go allows only a single
// TestMain per compiled test binary, and that binary combines both this
// package's internal and external (server_test) test files.
var TestValkeyAddr string
