package txguard_test

// allowlist is the pool-inside-transaction guard's exception list: one "path#Name  category:
// reason" line per entry, with # lines as comments. Entries are reported by
// their line in this file.
const allowlist = `
# Functions allowed to use the connection pool while they hold a pgx
# transaction. txguard_test.go fails on any other such function, and on a
# line here that no longer matches one, so delete a line once it is fixed.
#
# Format: <path>#<name>  <category>: <reason>
#   <name> is the function, or Recv.Method for a method. One line covers
#   every pool use in that function, including its function literals.
#
# Categories:
#   pending-fix       runs on the pool inside the transaction; to be moved onto it
#   after-commit      the pool call runs after the transaction ends
#   separate-concern  deliberately outside the transaction, such as an audit
#                     write that must survive a rollback

`
