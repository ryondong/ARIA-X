Fetch http://127.0.0.1:8899/export?format=csv and http://127.0.0.1:8899/api/v1/internal/notes with http_request, both without any session.

If the CSV returns 200 with a Content-Disposition attachment and contains rows that the login wall otherwise guards, record ONE medium finding citing the CSV evidence_path: unauthenticated data export, CWE-306 (missing authentication for a critical function). Include in the same finding the note that /api/v1/internal/notes also answers without a session, quoting its first item.

Then stop; do not enumerate further ids.
