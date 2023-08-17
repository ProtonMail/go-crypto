cd gosop
echo "replace github.com/ProtonMail/go-crypto => ../go-crypto" >> go.mod
go get github.com/ProtonMail/go-crypto
go get github.com/ProtonMail/gopenpgp/v3/crypto@aebe43356421c682a82b22760174db4bd60b2fa5 
go build .
