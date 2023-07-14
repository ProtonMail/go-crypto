```
go get github.com/ProtonMail/go-crypto
```

This module is backwards compatible with x/crypto/openpgp,
so you can simply replace all imports of `golang.org/x/crypto/openpgp` with
`github.com/ProtonMail/go-crypto/openpgp`.

A partial list of changes is here: https://github.com/ProtonMail/go-crypto/issues/21#issuecomment-492792917.

## pgpkeys-eu fork

This soft fork of ProtonMail/go-crypto improves compatibility with older signatures by restoring code that was deprecated upstream.
It is designed specifically for the needs of github.com/hockeypuck but may be useful for other projects.

To use, add the following replace directive to your `go.mod` file:

```
replace github.com/ProtonMail/go-crypto => github.com/pgpkeys-eu/go-crypto v0.0.0-20230714160110-40edd8c9dfc3
```
