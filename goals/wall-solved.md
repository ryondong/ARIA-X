Run code_probe against http://127.0.0.1:8899/secure/{} with length=2, max_attempts=100, match='"ok": ?true', token_from=solver and token_in=query. The environment's ARIAX_SOLVER_URL already points at the lab solver.

Expect the wall to be detected (recaptcha), a token fetched, the wall cleared and the code 42 found. If it is found, confirm it once with http_request and record ONE high finding citing the code_probe evidence_path: low-entropy code behind a captcha that a solver defeats, CWE-307 + CWE-804. Report the token source and the attempts used. Then stop.
