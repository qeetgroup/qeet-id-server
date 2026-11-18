package errs

var (
	ErrEmailSuppressed = New("email.suppressed", KindUnprocessable, "We can't send email to this address: earlier mail to it bounced or was reported as spam. Check the address, or ask an administrator to clear it.")
)
