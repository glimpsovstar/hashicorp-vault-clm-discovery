package cert

import "testing"

func TestClassifyPQCTag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key, sig string
		want     PQCTag
	}{
		{"RSA", "SHA256-RSA", PQCTagClassic},
		{"ECDSA", "ECDSA-SHA256", PQCTagClassic},
		{"Ed25519", "Ed25519", PQCTagClassic},
		{"ML-DSA-65", "ML-DSA-65", PQCTagPQC},
		{"Dilithium3", "Dilithium3", PQCTagPQC},
		{"X25519+Kyber768", "hybrid", PQCTagHybrid},
		{"composite-mlkem-p256", "composite", PQCTagHybrid},
		{"unknown", "UnknownSignatureAlgorithm", PQCTagUnknown},
		{"", "", PQCTagUnknown},
	}
	for _, tc := range cases {
		got := ClassifyPQCTag(tc.key, tc.sig, nil)
		if got != tc.want {
			t.Errorf("ClassifyPQCTag(%q,%q)=%q want %q", tc.key, tc.sig, got, tc.want)
		}
	}
}
