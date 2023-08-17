cd gosop
echo "replace github.com/ProtonMail/go-crypto => ../go-crypto" >> go.mod
go get github.com/ProtonMail/go-crypto
go get github.com/ProtonMail/gopenpgp/v3/crypto@26e397f0942ab02ec6649ebd30c71d0421131df8 
go build .
