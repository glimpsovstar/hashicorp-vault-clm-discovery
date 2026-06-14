/**
 * Official Vault product mark from HashiCorp Flight Icons (`vault-color-24`).
 * Vault UI uses the same glyph: Hds::AppHeader::HomeLink @icon="vault"
 * in hashicorp/vault ui/lib/core/addon/components/sidebar/frame.hbs
 *
 * SPDX-License-Identifier: MPL-2.0 (Flight Icons)
 */
export default function VaultLogo({ size = 24 }: { size?: number }) {
  return (
    <svg
      className="app-header-logo"
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        fill="#FFCF25"
        d="M1 1l10.96 21.334L23 1H1zm9.256 8.469H8.51V7.723h1.746v1.746zm0-2.62H8.51V5.105h1.746v1.744zm2.618 5.238h-1.746v-1.746h1.746v1.746zm0-2.618h-1.746V7.723h1.746v1.746zm0-2.62h-1.746V5.105h1.746v1.744zm2.604 2.62h-1.746V7.723h1.746v1.746zm-1.746-2.62V5.105h1.746v1.744h-1.746z"
      />
    </svg>
  );
}
