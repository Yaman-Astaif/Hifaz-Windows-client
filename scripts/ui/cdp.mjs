// A minimal Chrome DevTools Protocol client for the UI tests (Node 22+,
// built-in fetch and WebSocket). It talks to the app's WebView2 through
// the debugging port the app opens when HIFAZ_WEBVIEW_DEBUG_PORT is set.
import { writeFile } from "node:fs/promises";

export async function connect(port, { timeoutMs = 60000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let page;
  while (!page) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      page = targets.find((t) => t.type === "page");
    } catch { /* not up yet */ }
    if (!page) {
      if (Date.now() > deadline) throw new Error(`no WebView2 page on port ${port}`);
      await sleep(500);
    }
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail; });
  let next = 0;
  const pending = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) {
      const { ok, fail } = pending.get(m.id);
      pending.delete(m.id);
      m.error ? fail(new Error(JSON.stringify(m.error))) : ok(m.result);
    }
  };
  const send = (method, params = {}) => new Promise((ok, fail) => {
    const id = ++next;
    pending.set(id, { ok, fail });
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(`page error: ${JSON.stringify(r.exceptionDetails)}`);
    return r.result.value;
  };
  const screenshot = async (file) => {
    const r = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(file, Buffer.from(r.data, "base64"));
  };
  return { page, send, evaluate, screenshot, close: () => ws.close() };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// waitFor polls a page expression until it is truthy.
export async function waitFor(cdp, expression, what, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let v;
    try { v = await cdp.evaluate(expression); } catch { v = undefined; }
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}
