Run http_matrix on http://127.0.0.1:8899/admin with family=auth_presence (tool http_matrix, url, family).

The baseline unauthenticated GET returns 302 to /login. Exactly one or two path variants are expected to return 200 with the admin console body — that is an authorization gap on route normalization, not a redirect difference.

If a variant returns 200 AND its body excerpt contains "Admin console", record ONE high finding citing that row's evidence_path: missing authorization on the trailing-slash/encoded path variant, CWE-425 (direct request) with CWE-288 (relying on path, not session). Also record a fact listing every variant that differed from the baseline and how. Then stop.
