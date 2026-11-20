Open a session with http_session (action=open, name=alice, url=http://127.0.0.1:8899/login, method POST, body username=alice&password=alicepw1). Confirm the session works by sending GET http://127.0.0.1:8899/account/1 with action=send.

Then send GET /account/2 with the same session. If it returns 200 with a body naming bob (not alice), the object reference is not bound to the session: broken object-level authorization, CWE-639.

Record ONE high finding citing that response's evidence_path and a fact naming both readable ids. Then stop.
