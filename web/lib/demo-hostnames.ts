/** Keep in sync with internal/demo/hostnames.go (enforced by Go test TestWebDemoHostnamesMatchGo). */
export const DEMO_SCAN_HOSTNAMES = [
  "aap.david-joo.sbx.hashidemos.io",
  "coffeesnob.withdevo.net",
] as const;

export const DEMO_SCAN_HOSTNAMES_CSV = DEMO_SCAN_HOSTNAMES.join(",");
