A browser already holds the login cookie for http://127.0.0.1:8899: you only have the cookie string, not the password.

Open a session with http_session action=open name=seed against http://127.0.0.1:8899/login POST body username=alice&password=alicepw1 to obtain that cookie, then call http_session action=list reveal=true to read it (the field cookie_header).

Re-seed a second, independent session the way a browser import works: http_session action=import name=browser url=http://127.0.0.1:8899/account/1 cookies="sid=<value from cookie_header>".

Send GET /account/2 through the imported session. If it answers 200 naming bob, record ONE high finding citing that evidence_path: object-level authorization broken, reachable from an imported browser session, CWE-639. Emphasise that no login form was used after the import. Record also a fact with the imported cookie header masked. Then stop.
