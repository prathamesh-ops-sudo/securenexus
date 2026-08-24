ALTER TABLE "vuln_findings"
  ADD COLUMN IF NOT EXISTS "advisory_ecosystem" text;
