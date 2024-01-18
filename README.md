```
go get github.com/ProtonMail/go-crypto
```

This module is backwards compatible with x/crypto/openpgp,
so you can simply replace all imports of `golang.org/x/crypto/openpgp` with
`github.com/ProtonMail/go-crypto/openpgp`.

A partial list of changes is here: https://github.com/ProtonMail/go-crypto/issues/21#issuecomment-492792917.

For the more extended API for reading and writing OpenPGP messages use `github.com/ProtonMail/go-crypto/openpgp/v2`, but it is not fully backwards compatible with `golang.org/x/crypto/openpgp`. 
