# Version 2 Update

This document summarizes the major changes for reading and writing OpenPGP message introduced by `ProtonMail/go-crypto/openpgp/v2` compared to `ProtonMail/go-crypto/openpgp`.


## Import

The v2 API can be imported as:
```
openpgp ProtonMail/go-crypto/openpgp/v2
```

## API breaking changes

`openpgp.v2.Entity` struct fields have changed:
- `SelfSignature *packet.Signature` removed
- `Signatures []*packet.Signature` removed
- `DirectSignatures []*packet.VerifiableSignature` added
- `Revocations []*packet.VerifiableSignature` changed type
  
`openpgp.v2.Entity` changed API methods:
- `PrimaryIdentity(date time.Time)` has a time argument now.
- `EncryptionKey(date time.Time, config *packet.Config)` has a new config argument.
- `CertificationKey(date time.Time, config *packet.Config)` has a new config argument.
- `CertificationKeyById(date time.Time, id uint64, config *packet.Config)` has a new config argument.
- `SigningKey(date time.Time, config *packet.Config)` has a new config argument.
- `SigningKeyById(date time.Time, id uint64, config *packet.Config)` has a new config argument.
- `Revoke(reason packet.ReasonForRevocation, reasonText string, config *packet.Config)` changed name instead of RevokeKey.

`openpgp.v2.Entity` removed API methods:
- `RevokeSubkey(...) ` replaced by `(Subkey).Revoke(...)`

`openpgp.v2.Subkey` struct fields have changed:
- `Sig *packet.Signature` removed
- `Bindings []*packet.VerifiableSignature` added
- `Primary *Entity` added, points to the primary key.
- `Revocations []*packet.VerifiableSignature` changed type

`openpgp.v2.Subkey` changed API methods:
- `Revoked(selfCertification *packet.Signature, date time.Time)` has a new selfCertification argument, which points to the self signature to be used.

`openpgp.v2.Identity` struct fields have changed:
- `SelfSignature *packet.Signature` removed
- `Signatures []*packet.Signature ` removed
- `SelfCertifications []*packet.VerifiableSignature` added
- `OtherCertifications []*packet.VerifiableSignature` added
- `Primary *Entity` added, points to the primary key.
- `Revocations []*packet.VerifiableSignature` changed type

`openpgp.v2.Identity` changed API methods:
- `Revoked(selfCertification *packet.Signature, date time.Time)` has a new selfCertification argument, which points to the self signature to be used.

`openpgp.v2.Key` struct fields have changed:
- `PrimarySelfSignature *packet.Signature ` added, which points to the selected self signature of the primary key.
- `Revocations []*packet.VerifiableSignature` changed type

`openpgp.v2.KeyRing` interface has has changed:
- `KeysByIdUsage(...)` removed
- `DecryptionKeys(...)` removed
- `EntitiesById(id uint64) []*Entity` added. This is the main internal method to access keys from the keyring now.
  
`openpgp.v2.FileHints` struct field has changed:
- `IsBinary` removed  and `IsUTF8` added 
  
`openpgp.v2` API changes for reading messages:
- `VerifyDetachedSignatureAndHash(...)` removed, headers in clearsigned messages are no longer checked.
- `VerifyDetachedSignatureAndSaltedHash(...)` removed
- `CheckDetachedSignature(...)` removed, call `VerifyDetachedSignature(...)` instead
- `CheckDetachedSignatureAndSaltedHash(...)` removed 
- `CheckDetachedSignatureAndHash(...)` removed
- `CheckArmoredDetachedSignature` removed call `VerifyArmoredDetachedSignature` instead

`openpgp.v2` API changes for writing messages:
- `DetachSign(..., signers []*Entity,...)` takes now a slice of entities instead of a single entity as an argument.
- `ArmoredDetachSign(..., signers []*Entity,..., , params *SignParams)` takes now a slice of entities instead of a single entity as an argument and replaces arguments with a SignParams object.
- `DetachSignText(..., signers []*Entity,...)` takes now a slice of entities instead of a single entity as an argument.
- `ArmoredDetachSignText(..., signers []*Entity,...)` takes now a slice of entities instead of a single entity as an argument.
- `EncryptText(...)` removed call `EncryptWithParams(...)` instead
- `EncryptSplit(...)` removed call `EncryptWithParams(...)` instead
- `EncryptTextSplit(...)` removed call `EncryptWithParams(...)` instead
- `Encrypt(..., toHidden []*Entity, signers []*Entity)` now takes an additional toHidden recipients argument and takes now a slice of signer entities instead of a single entity as an argument.
- `Sign(..., signers []*Entity,...)` takes now a slice of entities instead of a single entity as an argument.

## Features added

### Intended recipients

Version 2 of the ProtonMail/go-crypto library introduces a feature for including the recipients' key fingerprints in signatures during message encryption.
When encrypting and signing a message, the intended recipients are automatically included in the signature, unless specifically hidden (i.e., hidden recipients). 
During the decryption process, if the signature contains intended recipients and the appropriate configuration flag is set, the library verifies whether the primary ID of the decryption key is present in the recipient list. 
This check can be disabled in the config when a hidden recipient decrypts the message.

### Multi-signature support

In previous iterations of ProtonMail/go-crypto, only a single signature creation and verification were supported in a PGP message. 
However, in Version 2, the library introduces the ability to sign messages with multiple signatures using different keys, such as a v4 and a v6 key.
The encryption and signing methods now accept multiple signing keys as arguments, with each key designated for a specific signature. 
When reading PGP messages with Version 2, the library maintains an internal state for each known signature and verifies all of them within the message.
To facilitate this functionality, the message details struct includes a new field that stores the verification state for each signature. A message is considered valid if at least one of the signatures successfully validates without any errors.
For callers, the process of checking for signature errors remains similar to previous versions. 
However, if the caller requires the verification state of all signatures, they can utilize the new field in the message details struct.

### Rework how signatures in keys and signatures are verified

In previous iterations of ProtonMail/go-crypto, key verification occurred during import based on the current time, while signature verification did not involve further key checks. 
However, this approach had limitations, as invalid keys could have been valid at the time of signature creation and mistakenly considered invalid.

Version 2 changes how and when signatures are verified in keys (i.e., direct-signatures, self-signatures of userids, binding signatures in subkeys, revocations, etc).
Unlike before, key signature verification no longer takes place during parsing. 
Instead, keys are now validated when they are utilized, following a similar approach to key handling in OpenPGP.js. 
Additionally, all signatures and expirations are validated to adhere to the key lifecycle outlined in the RFC.
The validity of keys can now be checked at different points in time, leading to the following specific modifications:
- During entity parsing, key validity is not checked.
- When used for encryption or signing, keys are verified using the current time during the writing process.
- During reading, the library verifies that each verification key was valid at the time of signature creation.
- A clear separation is maintained between Entity, Subkey, Identity, and their respective validation methods.
- Signature verification results are cached and reused to optimize computation.

Further, version 2 includes various small improvements to increase the robustness of the key parsing functions. 

### Weak algorithm rejection

Version 2 introduces the option to specify weak algorithms for signatures in the config.
Signatures that use weak algorithms are considered invalid.

### Optional packet sequence checker

Version 2 introduces a new feature that enables the validation of packet sequences in PGP messages. 
This functionality can be enabled in the config struct.
In particular, it implements the pushdown automata (PDA) from PGPainless, developed by Paul Schaub. 
By leveraging this feature, users can ensure that the packet sequences in their PGP messages are valid and comply with the required structure. 
This addition further enhances the overall reliability and security of PGP message handling in Version 2.

### Session key encryption and decryption

Version 2 allows advanced users to retrieve the session key while encrypting a message by setting the respective flag in the config.
In decryption, a caller can provide a session key that should be used for decryption.

### Unify write/read API

Version 2 improves the compatibility between different APIs to allow combinations. 
The `DetachSign` function requires the caller to provide a `Reader` for the message, while
encrypt returns a `WriteCloser` to which the message is written to.
The new version adds a function `DetachSignWriter`, which returns a `WriteCloser` similar to the encryption API.
On the reading side, the verify detached signature API now relies on the
same signature verification logic as the other read functions. 
Additionally, a new `VerifyDetachedSignatureReader` method similar to the `ReadMessage` API is introduced.
It returns a message details struct that once read verifies the signature.
Allows to chain different readers from the API, for example, to have a streaming API for encrypted detached signatures.

### Params struct as a function argument in the write API 

With the inclusion of new features, the write functions in go-crypto experienced significant growth in numbers. Each combination has its dedicated function. 
Version 2 introduces an `EncryptWithParams`/`SignWithParams` function that takes an `EncryptParams`/`SignParams` struct as an argument. The struct allows configuring the different features. 
This approach effectively reduces the number of API methods and simplifies the process of adding new features while maintaining compatibility with previous versions.

### Others

- Disable armor checksum on default `armor.Encode` method
- Make `unarmor` more robust to empty header values 
- Allow key generation of v6 keys without a `Identity`
- Allow compression in inline signed messages
- Consider key preferences in detached signatures
- Only compare time at a second granularity 
- Signal if tag is not verified on close in aead decryption
- Ensure that critical unknown packet tags result in message rejection
- Ensure that decompression streams are closed and that the packet is completely read
- Ensure that entity parsing does not reject keys with unknown subkeys 
- Check for known curves early when parsing ECDSA and ECDH keys
- Skip signatures with the wrong type while parsing an entity
- Support for signatures that appear in front of the data
- Change file hints field IsBinary to IsUTF8
