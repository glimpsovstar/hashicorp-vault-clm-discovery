package lifecycle

import "testing"

func TestChooseRecommendation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   ChooseInput
		want string // expected Code
	}{
		{"managed in vault wins", ChooseInput{CertScope: "internal", ManagedStatus: "managed_in_vault", ChainStatus: "incomplete", IsCA: true}, "already_managed"},
		{"incomplete chain", ChooseInput{CertScope: "internal", ManagedStatus: "unmanaged", ChainStatus: "incomplete"}, "fix_chain"},
		{"untrusted root", ChooseInput{CertScope: "external", ManagedStatus: "unmanaged", ChainStatus: "untrusted_root"}, "fix_chain"},
		{"unmanaged CA", ChooseInput{CertScope: "internal", ManagedStatus: "unmanaged", ChainStatus: "complete", IsCA: true}, "import_ca"},
		{"external leaf", ChooseInput{CertScope: "external", ManagedStatus: "unmanaged", ChainStatus: "complete"}, "migrate_vault"},
		{"internal leaf", ChooseInput{CertScope: "internal", ManagedStatus: "unmanaged", ChainStatus: "complete"}, "migrate_vault"},
		{"imported", ChooseInput{CertScope: "internal", ManagedStatus: "imported", ChainStatus: "complete"}, "migrate_vault"},
		{"self_signed leaf", ChooseInput{CertScope: "internal", ManagedStatus: "unmanaged", ChainStatus: "self_signed"}, "migrate_vault"},
		{"unknown scope leaf", ChooseInput{CertScope: "", ManagedStatus: "unmanaged", ChainStatus: "complete"}, "migrate_vault"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChooseRecommendation(tt.in)
			if got.Code != tt.want {
				t.Fatalf("code = %q, want %q", got.Code, tt.want)
			}
			if got.Title == "" || got.Rationale == "" {
				t.Fatalf("title/rationale must be populated: %+v", got)
			}
			if tt.want == "migrate_vault" && got.CTA != "Migrate to Vault" {
				t.Fatalf("CTA = %q", got.CTA)
			}
		})
	}
}
