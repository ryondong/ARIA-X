Fetch http://127.0.0.1:8899/api/rs/token?user=alice. The verifier at http://127.0.0.1:8899/api/rs/me reads the algorithm out of the token header.

Run jwt_sign alg=HS256 claims={"sub":"alice","role":"admin"} with key_pem set to the CONTENTS of lab/fixtures/keys/rsa.pub (the public key text is the HMAC secret — algorithm confusion), verify=true, and send the token as Authorization: Bearer.

If /api/rs/me returns 200 with role admin, immediately call add_finding with severity=high, evidence=<the jwt_sign evidence_path as a plain string>, and a body explaining that HS256 keyed with the public PEM was accepted: RS256→HS256 algorithm confusion, CWE-347 + CWE-436. Then stop.
