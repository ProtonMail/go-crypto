cd gosop
echo "replace github.com/ProtonMail/go-crypto => ../go-crypto" >> go.mod
go get github.com/ProtonMail/go-crypto
go get github.com/ProtonMail/gopenpgp/v3/crypto@c09849a05e9a6221a99bc1dd8731f36d16ea1757 
go build .
