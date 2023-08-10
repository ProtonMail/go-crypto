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

To use, run the following commands in your golang project (replace COMMIT_ID with the desired hash):

```
go mod edit -replace github.com/ProtonMail/go-crypto=github.com/pgpkeys-eu/go-crypto@COMMIT_ID
go mod tidy
```
