The lab publishes its JWT public key and leaks an RSA private key in lab/fixtures/keys (rsa.pem). Fetch http://127.0.0.1:8899/api/rs/token?user=alice and read the RS256 token from the JSON.

Run jwt_sign alg=RS256 claims={"sub":"alice","role":"admin"} key_file=<absolute path to rsa.pem> verify=true, then send the returned token to http://127.0.0.1:8899/api/rs/me as Authorization: Bearer.

If /api/rs/me returns 200 with role admin, immediately call add_finding with severity=high, evidence=<the jwt_sign evidence_path as a plain string>, and a body naming both the forged claim and the 200 response: forged RS256 token from a leaked private key, CWE-321 + CWE-345. Then stop.
