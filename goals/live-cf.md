Target: https://www.zoominfo.com — a real Cloudflare-protected home page.

First show the wall: http_request GET https://www.zoominfo.com and note the 403 plus challenge markers. Plain HTTP cannot pass it.

Then call browser_session action=open url=https://www.zoominfo.com wait=45 settle_ms=4000 import_to=cf screenshot=true. The browser runs the challenge itself; the wall should clear within ~15s and cf_clearance should appear in imported_cookies.

If cleared=true, PROVE the handoff: the imports include cf_clearance and the session carries the browser's UA. Replay the page with http_session action=send name=cf url=https://www.zoominfo.com. A 200 with the real page (not "Just a moment...") means the wall is beaten for plain HTTP too.

Then record ONE high finding with add_finding severity=high, evidence=<the browser evidence_path>, body naming both statuses (403 before, 200 after) and the rounds. Cite CWE-804. Then stop — do not crawl.
