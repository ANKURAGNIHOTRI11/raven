ALTER TABLE vulnerabilities
  ADD COLUMN IF NOT EXISTS os_families         text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS linux_distros       text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS architectures       text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS platform_basis      text   NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS platform_confidence real   NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS vuln_os_idx     ON vulnerabilities USING GIN (os_families);
CREATE INDEX IF NOT EXISTS vuln_distro_idx ON vulnerabilities USING GIN (linux_distros);
CREATE INDEX IF NOT EXISTS vuln_arch_idx   ON vulnerabilities USING GIN (architectures);
CREATE INDEX IF NOT EXISTS vuln_sev_idx    ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS vuln_cvss_idx   ON vulnerabilities (cvss_base DESC);
CREATE INDEX IF NOT EXISTS vuln_pub_idx    ON vulnerabilities (published DESC);
