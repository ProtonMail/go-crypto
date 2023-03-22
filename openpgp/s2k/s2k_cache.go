package s2k

// Cache stores keys derived with s2k functions from one passphrase
// to avoid recomputation if multiple items are encrypted with
// the same parameters.
type Cache struct {
	derivedKeyCache map[Params][]byte
}

// NewCache creates a new emtpy s2k cache for
// reusing keys 
func NewCache() *Cache {
	return &Cache{
		derivedKeyCache: make(map[Params][]byte),
	}
}

// add adds a derived key to the cache.
func (c *Cache) addDeriveKey(params *Params, key []byte) {
	c.derivedKeyCache[*params] = key
}

// GetDerivedKeyOrElseCompute tries to retrive the key 
// for the given s2k parameters from the cache.
// If there is no hit, it derives the key with the s2k function from the passphrase,
// updates the cache, and returns the key.
func (c *Cache) GetDerivedKeyOrElseCompute(passphrase []byte, params *Params, expectedKeySize int) ([]byte, error) {
	key, found := c.derivedKeyCache[*params]
	if !found || expectedKeySize != len(key) {
		var err error
		derivedKey := make([]byte, expectedKeySize)
		s2k, err := params.Function()
		if err != nil {
			return nil, err
		}
		s2k(derivedKey, passphrase)
		c.addDeriveKey(params, derivedKey)
		return derivedKey, nil
	}
	return key, nil
}

// Reset clears the cache.
func (c *Cache) Reset() {
	c.derivedKeyCache = make(map[Params][]byte)
}
