Probe http://127.0.0.1:8899/secure/00 with http_request and read the body.

The response is 200, so a status-only reader calls this a working route. Check the body: it carries a "Just a moment..." title and a data-sitekey widget, i.e. a bot wall.

Run code_probe against http://127.0.0.1:8899/secure/{} with length=2, max_attempts=20 and match='"ok": ?true', with no token channel. If it returns blocked=true, record ONE medium finding citing the code_probe evidence_path: a captcha wall masked as a 200, so the code route is BLOCKED rather than absent — CWE-804 with a note on the false-negative risk. Quote the wall vendor and reaction. Then stop.
