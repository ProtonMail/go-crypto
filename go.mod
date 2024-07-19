module github.com/ProtonMail/go-crypto

go 1.21

require (
	github.com/cloudflare/circl v1.3.7
	golang.org/x/crypto v0.25.0
)

require golang.org/x/sys v0.22.0 // indirect

replace github.com/cloudflare/circl v1.3.7 => github.com/wussler/circl v0.0.0-20240227155518-22e2dd8861f2
