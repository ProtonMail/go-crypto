cd gosop
echo "replace github.com/ProtonMail/go-crypto => ../go-crypto" >> go.mod
go get github.com/ProtonMail/go-crypto
go get github.com/ProtonMail/gopenpgp/v3/crypto@80762a9ce60ba09d8a0d4f7b2a9a9665e7716351 
go build .
