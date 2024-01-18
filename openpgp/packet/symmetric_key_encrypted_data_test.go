package packet

// These test vectors contain V4 or V5 symmetric key encrypted packets followed
// by an integrity protected packet (SEIPD v1 or v2).

type packetSequence struct {
	password string
	packets  string
	contents string
}

var keyAndIpePackets = []*packetSequence{symEncTestv6, aeadEaxRFC, aeadOcbRFC}

// https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-00.html#name-complete-aead-eax-encrypted-
var aeadEaxRFC = &packetSequence{
	password: "password",
	packets:  "c33e0507010308cd5a9f70fbe0bc6590bc669e34e500dcaedc5b32aa2dab02359dee19d07c3446c4312a34ae1967a2fb7e928ea5b4fa8012bd456d1738c63c36d44a0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476",
	contents: "cb1462000000000048656c6c6f2c20776f726c64210a",
}

// https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-00.html#name-complete-aead-ocb-encrypted-
var aeadOcbRFC = &packetSequence{
	password: "password",
	packets:  "c33d05070203089f0b7da3e5ea64779099e326e5400a90936cefb4e8eba08c6773716d1f2714540a38fcac529949dac529d3de31e15b4aeb729e330033dbedd4490107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098",
	contents: "cb1462000000000048656c6c6f2c20776f726c64210a",
}

// OpenPGP crypto refresh A.7.1.
var symEncTestv6 = &packetSequence{
	password: "password",
	packets:  "c33c061a07030b0308e9d39785b2070008ffb42e7c483ef4884457cb3726b9b3db9ff776e5f4d9a40952e2447298851abfff7526df2dd554417579a7799fd26902070306fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9ffc6fc6d65bbfd24dcd0790966e6d1e85a30053784cb1d8b6a0699ef12155a7b2ad6258531b57651fd7777912fa95e35d9b40216f69a4c248db28ff4331f1632907399e6ff9",
	contents: "cb1362000000000048656c6c6f2c20776f726c6421d50e1ce2269a9eddef81032172b7ed7c",
}
