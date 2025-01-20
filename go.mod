module github.com/ProtonMail/go-crypto

go 1.22.0

require (
	github.com/cloudflare/circl v1.5.0
	golang.org/x/crypto v0.25.0
)

require golang.org/x/sys v0.22.0 // indirect

replace github.com/cloudflare/circl v1.5.0 => github.com/lubux/circl v0.0.0-20241113220611-a91ad6141f93
