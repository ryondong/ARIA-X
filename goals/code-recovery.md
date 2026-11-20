Run code_probe against http://127.0.0.1:8899/otp/{} with length=2, max_attempts=100, xff_rotate=true and match='"ok": ?true'.

The app rate-limits per IP after 6 attempts, so the X-Forwarded-For rotation is the point of the run. When a code is found, confirm it with a single http_request to the same URL and record ONE high finding citing the code_probe evidence_path: low-entropy one-time code with no lockout and a spoofable limiter key, CWE-307 with CWE-330. Report the attempts used and the rate. Then stop.
