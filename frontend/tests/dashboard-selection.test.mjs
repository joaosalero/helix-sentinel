import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { test } from "node:test";
import next from "next";

// Exercise the built Next route and record only its requests to a loopback API.
test("the dashboard carries a selected alert and its tenant into the investigation", async (t) => {
  const alertId = "11111111-1111-4111-8111-111111111111";
  const requests = [];
  const api = createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    requests.push(url);
    if (url.pathname === `/detections/alerts/${alertId}`) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        event_time: "2026-01-01T12:00:00Z",
        source_name: "fixture",
        category: "system",
      }));
      return;
    }
    res.writeHead(503, { "content-type": "application/json" });
    res.end(JSON.stringify({ detail: "Synthetic routing fixture" }));
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  t.after(() => api.close());
  process.env.HELIX_API_BASE_URL = `http://127.0.0.1:${api.address().port}`;
  delete process.env.HELIX_API_TOKEN;

  const app = next({ dev: false, hostname: "127.0.0.1" });
  await app.prepare();
  t.after(() => app.close());
  const web = createServer(app.getRequestHandler());
  web.listen(0, "127.0.0.1");
  await once(web, "listening");
  t.after(() => web.close());
  const origin = `http://127.0.0.1:${web.address().port}/`;

  const response = await fetch(`${origin}?alert_id=${alertId}&tenant_id=demo&tenant_id=other`);
  assert.equal(response.status, 200);
  await response.text();
  assert.ok(requests.some((url) => url.pathname === `/detections/alerts/${alertId}`));
  assert.ok(requests.some((url) =>
    url.pathname === "/analytics/events" && url.searchParams.get("source") === "fixture"));
  assert.ok(requests.every((url) => url.searchParams.get("tenant_id") === "demo"));

  for (const query of ["", "?alert_id=invalid"]) {
    requests.length = 0;
    const unselected = await fetch(origin + query);
    assert.equal(unselected.status, 200);
    await unselected.text();
    assert.ok(requests.some((url) => url.pathname === "/detections/alerts"));
    assert.ok(requests.every((url) =>
      !url.pathname.startsWith("/detections/alerts/") && !url.searchParams.has("tenant_id")));
  }
});
