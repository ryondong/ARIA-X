Probe http://127.0.0.1:8899/login (method POST, body username=USER&password=x) three times with the tool http_request: username=alice, username=nosuchuser, and username=alice with the correct password alicepw1.

Compare status codes and body excerpts. A distinct message or status for an unknown user versus a wrong password is username enumeration (CWE-204). The correct-password attempt should 302 to /account/1 and set a cookie.

Record ONE medium finding citing the evidence of the two failing attempts, plus a fact with the exact wording of both messages. Then stop.
