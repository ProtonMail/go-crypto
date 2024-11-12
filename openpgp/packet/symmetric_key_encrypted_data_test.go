package packet

// These test vectors contain V4 or V5 symmetric key encrypted packets followed
// by an integrity protected packet (SEIPD v1 or v2).

type packetSequence struct {
	password         string
	packets          string
	contents         string
	faultyDataPacket string
}

func keyAndIpePackets() []*packetSequence {
	if V5Disabled {
		return []*packetSequence{symEncRFC9580, symEncRFC4880}
	}
	return []*packetSequence{symEncRFC9580, symEncRFC4880, aeadEaxRFC, aeadOcbRFC}
}

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

// From OpenPGP RFC9580 A.9 https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-aead-eax-encryption-
var symEncRFC9580 = &packetSequence{
	password: "password",
	packets:  "c340061e07010b0308a5ae579d1fc5d82bff69224f919993b3506fa3b59a6a73cff8c5efc5f41c57fb54e1c226815d7828f5f92c454eb65ebe00ab5986c68e6e7c55d269020701069ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb15431dfef5f5e2255ca78261546e339a",
	contents: "cb1362000000000048656c6c6f2c20776f726c6421d50eae5bf0cd6705500355816cb0c8ff",
	// Missing last authentication chunk
	faultyDataPacket: "d259020701069ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb",
}

// From the OpenPGP interoperability test suite (Test: S2K mechanisms, iterated min + esk)
var symEncRFC4880 = &packetSequence{
	password: "password",
	packets:  "c32e0409030873616c7a6967657200080674a0d96a4a6e122b1d5bbaa3fac117b9cbb46c7e38f12967386b57e2f79d11d23f01cee77ceed8544e6d52c78bd33c81bd366c8673b68955ddbd1ade98fe6a9b4e27ae54cd10dda7cd3a4637f44e0ead895ebebdcf0c679f1342745628f104e7",
	contents: "cb1462000000000048656c6c6f20576f726c64203a29",
}
