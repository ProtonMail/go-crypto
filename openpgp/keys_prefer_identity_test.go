package openpgp

import (
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// A public key can carry a user ID whose self-signature is absent: for example
// a user ID that only has a revocation, or one whose self-signature failed to
// verify. Such an identity is stored with a nil SelfSignature.
// shouldPreferIdentity must not dereference a nil SelfSignature regardless of
// whether the empty identity is the existing primary or the candidate.
// Otherwise PrimaryIdentity panics for a fraction of runs, because it iterates
// the Identities map in a non-deterministic order.

func identityWithSelfSignature(name string, creationTime time.Time) *Identity {
	return &Identity{
		Name:          name,
		SelfSignature: &packet.Signature{CreationTime: creationTime},
	}
}

func TestShouldPreferIdentityNilSelfSignature(t *testing.T) {
	withSelfSig := identityWithSelfSignature("With self-sig <a@example.com>", time.Unix(1000, 0))
	nilSelfSig := &Identity{Name: "No self-sig <b@example.com>"}
	anotherNilSelfSig := &Identity{Name: "No self-sig either <c@example.com>"}

	tests := []struct {
		name      string
		existing  *Identity
		candidate *Identity
		want      bool
	}{
		{"candidate without self-signature keeps existing", withSelfSig, nilSelfSig, false},
		{"existing without self-signature prefers candidate", nilSelfSig, withSelfSig, true},
		{"both without self-signature prefers candidate", nilSelfSig, anotherNilSelfSig, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldPreferIdentity(test.existing, test.candidate); got != test.want {
				t.Errorf("shouldPreferIdentity() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPrimaryIdentityWithNilSelfSignature(t *testing.T) {
	withSelfSig := identityWithSelfSignature("With self-sig <a@example.com>", time.Unix(1000, 0))
	nilSelfSig := &Identity{Name: "No self-sig <b@example.com>"}

	entity := &Entity{
		Identities: map[string]*Identity{
			withSelfSig.Name: withSelfSig,
			nilSelfSig.Name:  nilSelfSig,
		},
	}

	// Identities is iterated in a randomized order, so repeat to surface the
	// order-dependent panic and to confirm the identity with a valid
	// self-signature is always chosen as primary.
	for range 100 {
		if primary := entity.PrimaryIdentity(); primary != withSelfSig {
			t.Fatalf("PrimaryIdentity() = %q, want the identity with a self-signature", primary.Name)
		}
	}
}
