Run artifact_probe on base_url http://127.0.0.1:8899 with tier=s,m.

Expect a served .env (sniff env-file), a served .git/config (sniff git-config) and a SQL dump (sniff sql-dump); note which paths returned SOFT404 and were therefore absent. Each HIT carries an evidence_path with a sha256 and an excerpt.

Record ONE high finding citing the .env evidence_path (deployment secrets in a served file, CWE-538) and a fact listing every HIT with its sniff type and every soft-404 so absence is explicit. Then stop — do not fetch .git objects in this run.
