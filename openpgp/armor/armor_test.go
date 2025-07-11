// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package armor

import (
	"bytes"
	"hash/adler32"
	"io"
	"testing"
)

func TestDecodeEncode(t *testing.T) {
	buf := bytes.NewBuffer([]byte(armorExample1))
	result, err := Decode(buf)
	if err != nil {
		t.Error(err)
	}
	expectedType := "PGP SIGNATURE"
	if result.Type != expectedType {
		t.Errorf("result.Type: got:%s want:%s", result.Type, expectedType)
	}
	if len(result.Header) != 1 {
		t.Errorf("len(result.Header): got:%d want:1", len(result.Header))
	}
	v, ok := result.Header["Version"]
	if !ok || v != "GnuPG v1.4.10 (GNU/Linux)" {
		t.Errorf("result.Header: got:%#v", result.Header)
	}

	contents, err := io.ReadAll(result.Body)
	if err != nil {
		t.Error(err)
	}

	if adler32.Checksum(contents) != 0x27b144be {
		t.Errorf("contents: got: %x", contents)
	}

	buf = bytes.NewBuffer(nil)
	w, err := Encode(buf, result.Type, result.Header)
	if err != nil {
		t.Error(err)
	}
	_, err = w.Write(contents)
	if err != nil {
		t.Error(err)
	}
	w.Close()

	if !bytes.Equal(buf.Bytes(), []byte(armorExample1)) {
		t.Errorf("got: %s\nwant: %s", buf.String(), armorExample1)
	}
}

func TestDecodeEmptyVersion(t *testing.T) {
	buf := bytes.NewBuffer([]byte(armorExampleEmptyVersion))
	result, err := Decode(buf)
	if err != nil {
		t.Error(err)
	}
	expectedType := "PGP SIGNATURE"
	if result.Type != expectedType {
		t.Errorf("result.Type: got:%s want:%s", result.Type, expectedType)
	}
	if len(result.Header) != 1 {
		t.Errorf("len(result.Header): got:%d want:1", len(result.Header))
	}
	v, ok := result.Header["Version"]
	if !ok || v != "" {
		t.Errorf("result.Header: got:%#v", result.Header)
	}
}

func TestLongHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte(armorLongLine))
	result, err := Decode(buf)
	if err != nil {
		t.Error(err)
		return
	}
	value, ok := result.Header["Version"]
	if !ok {
		t.Errorf("missing Version header")
	}
	if value != longValueExpected {
		t.Errorf("got: %s want: %s", value, longValueExpected)
	}
}

func TestWithWhitespace(t *testing.T) {
	buff := bytes.NewBuffer([]byte(armorWithWhitespace))
	armorWithWhitespace, err := Decode(buff)
	if err != nil {
		t.Error(err)
	}

	armorWithWhitespaceBody, err := io.ReadAll(armorWithWhitespace.Body)
	if err != nil {
		t.Error(err)
	}

	buff = bytes.NewBuffer([]byte(armorExampleEmptyVersion))
	armorWithOutWhitespace, err := Decode(buff)
	if err != nil {
		t.Error(err)
	}

	armorWithOutWhitespaceBody, err := io.ReadAll(armorWithOutWhitespace.Body)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(armorWithWhitespaceBody, armorWithOutWhitespaceBody) {
		t.Errorf("got: %s want: %s", armorWithWhitespaceBody, armorWithOutWhitespaceBody)
	}
}

const armorExample1 = `-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)

iJwEAAECAAYFAk1Fv/0ACgkQo01+GMIMMbsYTwQAiAw+QAaNfY6WBdplZ/uMAccm
4g+81QPmTSGHnetSb6WBiY13kVzK4HQiZH8JSkmmroMLuGeJwsRTEL4wbjRyUKEt
p1xwUZDECs234F1xiG5enc5SGlRtP7foLBz9lOsjx+LEcA4sTl5/2eZR9zyFZqWW
TxRjs+fJCIFuo71xb1g=
=/teI
-----END PGP SIGNATURE-----`

const armorLongLine = `-----BEGIN PGP SIGNATURE-----
Version: 0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz

iQEcBAABAgAGBQJMtFESAAoJEKsQXJGvOPsVj40H/1WW6jaMXv4BW+1ueDSMDwM8
kx1fLOXbVM5/Kn5LStZNt1jWWnpxdz7eq3uiqeCQjmqUoRde3YbB2EMnnwRbAhpp
cacnAvy9ZQ78OTxUdNW1mhX5bS6q1MTEJnl+DcyigD70HG/yNNQD7sOPMdYQw0TA
byQBwmLwmTsuZsrYqB68QyLHI+DUugn+kX6Hd2WDB62DKa2suoIUIHQQCd/ofwB3
WfCYInXQKKOSxu2YOg2Eb4kLNhSMc1i9uKUWAH+sdgJh7NBgdoE4MaNtBFkHXRvv
okWuf3+xA9ksp1npSY/mDvgHijmjvtpRDe6iUeqfCn8N9u9CBg8geANgaG8+QA4=
=wfQG
-----END PGP SIGNATURE-----`

const longValueExpected = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"

const armorExampleEmptyVersion = `-----BEGIN PGP SIGNATURE-----
Version: 

wsE7BAABCgBvBYJkbfmWCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u
cy5zZXF1b2lhLXBncC5vcmeMXzsJEgIm228SdxV22XgYny4adwqEgyIT9UL3F92C
OhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAAj1AwAiSkJPxsEcyaoYWbxc657xPW1
MlrbNhDBIWpKVrqQgyz7NdDZvvY0Ty+/h62HK5GQ5obAzVmQVwtUVG950TxCksg1
F18mqticpxg1veZQdw7DBYTk0RJTpdVBRYJ5UOtHaSJUAnqGh7OQE6Lu74vfFhNv
dDjpjgEc6TnJrEBOOR7+RVp7+0i4HhM3+JdfSOMMOEb6ixWEYLtfC2Zd/p0f7vP8
tHiqllDXDbfBCXlFl5h2LAh39o/LE0vZvwf+C9i9PgRARawWIh+xeAJsVne8FZ12
FD+hWZJdNUCv4iE1H7QDVv8nuPAz3WB/DQWNSfeGTZnN+ouB1cjPFscBuunO5Dss
k3hXy+XB5mZW6iisjUnUBknJEa43AMX+zGSaGHljEgfTGLbgEK+deOhPqKEkhUKr
/VlIVBXgfjQuoizme9S9juxXHdDHa+Y5Wb9rTUc1y9YPArRem51VI0OzbJ2cRnLH
J0YF6lYvjcTVBtmQlYeOfZsz4EABEeBYe/rbDmJC
=b+IB
-----END PGP SIGNATURE-----`

const armorWithWhitespace = `-----BEGIN PGP SIGNATURE-----

	wsE7BAABCgBvBYJkbfmWCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u  
	cy5zZXF1b2lhLXBncC5vcmeMXzsJEgIm228SdxV22XgYny4adwqEgyIT9UL3F92C       
	OhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAAj1AwAiSkJPxsEcyaoYWbxc657xPW1     
	MlrbNhDBIWpKVrqQgyz7NdDZvvY0Ty+/h62HK5GQ5obAzVmQVwtUVG950TxCksg1
	F18mqticpxg1veZQdw7DBYTk0RJTpdVBRYJ5UOtHaSJUAnqGh7OQE6Lu74vfFhNv   
	dDjpjgEc6TnJrEBOOR7+RVp7+0i4HhM3+JdfSOMMOEb6ixWEYLtfC2Zd/p0f7vP8  
	tHiqllDXDbfBCXlFl5h2LAh39o/LE0vZvwf+C9i9PgRARawWIh+xeAJsVne8FZ12     
	FD+hWZJdNUCv4iE1H7QDVv8nuPAz3WB/DQWNSfeGTZnN+ouB1cjPFscBuunO5Dss    
	k3hXy+XB5mZW6iisjUnUBknJEa43AMX+zGSaGHljEgfTGLbgEK+deOhPqKEkhUKr
	/VlIVBXgfjQuoizme9S9juxXHdDHa+Y5Wb9rTUc1y9YPArRem51VI0OzbJ2cRnLH  
	J0YF6lYvjcTVBtmQlYeOfZsz4EABEeBYe/rbDmJC
    =b+IB
-----END PGP SIGNATURE-----`
