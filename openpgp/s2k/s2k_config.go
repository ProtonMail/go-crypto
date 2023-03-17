package s2k

import "crypto"

// Config collects configuration parameters for s2k key-stretching
// transformations. A nil *Config is valid and results in all default
// values.
type Config struct {
	// S2K (String to Key) mode, used for key derivation in the context of secret key encryption
	// and password-encrypted data. Either s2k.Argon2S2K or s2k.IteratedSaltedS2K has to be selected
	// weaker options are not allowed.
	// Note: Argon2 is the strongest option but not all OpenPGP implementations are compatible with it
	//(pending standardisation).
	// 0 (simple), 1(salted), 3(iterated), 4(argon2)
	// 2(reserved) 100-110(private/experimental).
	S2KMode Mode
	// Only relevant if S2KMode is not set to s2k.Argon2S2K.
	// Hash is the default hash function to be used. If
	// nil, SHA256 is used.
	Hash crypto.Hash
	// Argon2 parameters for S2K (String to Key).
	// Only relevant if S2KMode is set to s2k.Argon2S2K.
	// If nil, default parameters are used.
	// For more details on the choice of parameters, see https://tools.ietf.org/html/rfc9106#section-4.
	ArgonConfig *ArgonConfig
	// Only relevant if S2KMode is set to s2k.IteratedSaltedS2K.
	// Iteration count for Iterated S2K (String to Key). It
	// determines the strength of the passphrase stretching when
	// the said passphrase is hashed to produce a key. S2KCount
	// should be between 65536 and 65011712, inclusive. If Config
	// is nil or S2KCount is 0, the value 16777216 used. Not all
	// values in the above range can be represented. S2KCount will
	// be rounded up to the next representable value if it cannot
	// be encoded exactly. When set, it is strongly encrouraged to
	// use a value that is at least 65536. See RFC 4880 Section
	// 3.7.1.3.
	S2KCount int
}

// ArgonConfig stores the Argon2 parameters
// A nil *ArgonConfig is valid and results in all default
type ArgonConfig struct {
	NumberOfPasses      uint8
	DegreeOfParallelism uint8
	// The memory parameter for Argon2 specifies desired memory usage in kibibytes. 
	// For example memory=64*1024 sets the memory cost to ~64 MB.
	Memory      	    uint32 
}

func (c *Config) Mode() Mode {
	if c == nil {
		return IteratedSaltedS2K
	}
	return c.S2KMode
}

func (c *Config) hash() crypto.Hash {
	if c == nil || uint(c.Hash) == 0 {
		return crypto.SHA256
	}

	return c.Hash
}

func (c *Config) Argon2() *ArgonConfig {
	if c == nil || c.ArgonConfig == nil {
		return nil
	}
	return c.ArgonConfig
}

// EncodedCount get encoded count
func (c *Config) EncodedCount() uint8 {
	if c == nil || c.S2KCount == 0 {
		return 224 // The common case. Corresponding to 16777216
	}

	i := c.S2KCount

	switch {
	case i < 65536:
		i = 65536
	case i > 65011712:
		i = 65011712
	}

	return encodeCount(i)
}

func (c *ArgonConfig) Passes() uint8 {
	if c == nil || c.NumberOfPasses == 0 {
		return 3
	}
	return c.NumberOfPasses
}

func (c *ArgonConfig) Parallelism() uint8 {
	if c == nil || c.DegreeOfParallelism == 0 {
		return 4
	}
	return c.DegreeOfParallelism
}

func (c *ArgonConfig) EncodedMemory() uint8 {
	if c == nil || c.Memory == 0 {
		return 16 // 64 MiB of RAM
	}

	temp := c.Memory
	lowerBound := uint32(c.Parallelism())*8
	upperBound := uint32(2147483648)

	switch {
	case temp < lowerBound:
		temp = lowerBound
	case temp > upperBound:
		temp = upperBound
	}

	return encodeMemory(temp, c.Parallelism())
}
