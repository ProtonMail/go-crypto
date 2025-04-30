module github.com/ProtonMail/go-crypto

go 1.22.0

require (
	github.com/cloudflare/circl v1.6.0
	golang.org/x/crypto v0.33.0
)

require golang.org/x/sys v0.30.0 // indirect

replace github.com/cloudflare/circl v1.6.0 => github.com/ProtonMail/circl v0.0.0-20250505075934-8c9cec5c8dd7
