module github.com/ProtonMail/go-crypto

go 1.21

toolchain go1.22.0

require (
	github.com/cloudflare/circl v1.3.7
	github.com/kasperdi/SPHINCSPLUS-golang v0.0.0-20221227220735-de985e5a663c
	golang.org/x/crypto v0.17.0
)

require golang.org/x/sys v0.16.0 // indirect

replace github.com/cloudflare/circl v1.3.7 => github.com/wussler/circl v0.0.0-20240227155518-22e2dd8861f2
