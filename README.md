```
go get github.com/ProtonMail/go-crypto
```

This module is backwards compatible with x/crypto/openpgp,
so you can simply replace all imports of `golang.org/x/crypto/openpgp` with
`github.com/ProtonMail/go-crypto/openpgp`.

A partial list of changes is here: https://github.com/ProtonMail/go-crypto/issues/21#issuecomment-492792917.

## pgpkeys-eu fork

To use this soft fork, you should use the following replace directive in your `go.mod` file:

```
replace github.com/ProtonMail/go-crypto => github.com/pgpkeys-eu/go-crypto v0.0.0-20230506215654-16de0cc09494
```
