Fetch http://127.0.0.1:8899/js/42 with http_request and note that the body is a "Just a moment..." challenge page although the status is 200 — plain HTTP cannot run the challenge script.

Now run browser_session action=open url=http://127.0.0.1:8899/js/42 wait=20 import_to=jswall settle_ms=1200 screenshot=true. The browser executes the page's own script, the wall clears and a jsok cookie is minted.

If cleared=true and jsok is in imported_cookies, record ONE high finding citing the browser evidence_path: a JS-only bot wall that a headless browser clears and whose clearance cookie outlives it, CWE-804 + CWE-1004 context. Quote the rounds used. Then stop.
