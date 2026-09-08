import test from "node:test";
import assert from "node:assert/strict";
import { faviconSourceForTab, createFaviconLoader } from "../firefox-extension/shared/service-icons.js";

const PAGE = "https://eu-west-1.console.aws.amazon.com/s3/home";
const ICON = "https://assets.console.awsstatic.com/synthetic/favicon.svg";
const tab = (favIconUrl = ICON, url = PAGE) => ({ url, favIconUrl });
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="6" fill="orange"/></svg>';
const response = (body = SVG, headers = {}) => new Response(body, {
  headers: { "content-type": "image/svg+xml", ...headers },
});

test("actual embedded PNG, SVG and browser-local favicons take priority on all tabs", async () => {
  const load = createFaviconLoader({ fetchImpl: () => { throw new Error("Must not request local icons"); } });
  for (const url of [PAGE, "https://example.invalid/", "about:blank"]) {
    for (const icon of [
      "data:image/png;base64,iVBORw0KGgo=",
      "data:image/svg+xml," + encodeURIComponent(SVG),
      "data:image/svg+xml;charset=utf-8," + encodeURIComponent(SVG),
      "data:image/svg+xml;base64," + btoa(SVG),
      "moz-extension://synthetic-extension/icons/icon.png",
    ]) {
      assert.deepEqual(faviconSourceForTab(tab(icon, url)), { url: icon, remote: false });
      assert.equal(await load(tab(icon, url)), icon);
    }
  }
});

test("only browser-reported static AWS favicons on actual AWS console tabs can be fetched", () => {
  for (const host of ["console.aws.amazon.com", "eu-west-1.console.aws.amazon.com", "d1.awsstatic.com", "assets.console.awsstatic.com"]) {
    for (const ext of ["ico", "png", "jpg", "jpeg", "gif", "webp", "svg"]) {
      const url = "https://" + host + "/assets/favicon." + ext;
      assert.deepEqual(faviconSourceForTab(tab(url)), { url, remote: true });
    }
  }
  assert.equal(faviconSourceForTab(tab(ICON, "https://d-synthetic.studio.eu-west-1.sagemaker.aws/")).remote, true);
  assert.equal(faviconSourceForTab(tab(ICON + "#decorative")).url, ICON);
  assert.equal(faviconSourceForTab({ url: PAGE, title: "S3 buckets" }), null);
});

test("rejects arbitrary hosts, auth/query URLs, invalid schemes, spoofed AWS pages and oversized data", async () => {
  let calls = 0;
  const load = createFaviconLoader({ fetchImpl: () => { calls++; } });
  const badIcons = [
    undefined, null, {}, 42, "", "/favicon.ico", "javascript:alert(1)",
    "file:///tmp/favicon.ico", "blob:https://example.invalid/synthetic",
    "data:text/html,<img>", "data:image/svg+xmlX,<svg/>",
    "data:image/png;base64," + "A".repeat(128 * 1024),
    "https://example.invalid/favicon.ico", "http://console.aws.amazon.com/favicon.ico",
    "https://assets.console.awsstatic.com.example.invalid/favicon.ico",
    "https://console.aws.amazon.com:8443/favicon.ico",
    "https://synthetic:synthetic@console.aws.amazon.com/favicon.ico",
    ICON + "?token=__CONTAINOODLE_TEST_NOT_A_TOKEN__",
    "https://console.aws.amazon.com/federation",
    "https://console.aws.amazon.com/path%2Ffavicon.ico",
    "https://signin.aws.amazon.com/favicon.ico",
    "https://127.0.0.1/favicon.ico",
  ];
  for (const icon of badIcons) assert.equal(await load({ url: PAGE, favIconUrl: icon }), null, String(icon));
  for (const url of [undefined, "https://example.invalid/s3", "http://console.aws.amazon.com/",
    "https://console.aws.amazon.com.example.invalid/", "https://synthetic@console.aws.amazon.com/"]) {
    assert.equal(await load({ url, favIconUrl: ICON }), null, String(url));
  }
  assert.equal(calls, 0);
});

test("remote originals use credential-free, referrer-free, no-redirect CORS fetch and in-memory deduplication", async () => {
  const calls = [];
  const load = createFaviconLoader({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return response();
  } });
  const [first, second] = await Promise.all([load(tab()), load(tab())]);
  assert.equal(first, "data:image/svg+xml;base64," + btoa(SVG));
  assert.equal(second, first);
  assert.equal(await load(tab()), first);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, ICON);
  assert.equal(calls[0].options.credentials, "omit");
  assert.equal(calls[0].options.referrerPolicy, "no-referrer");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.mode, "cors");
  assert.equal(calls[0].options.headers, undefined);
  assert.equal(calls[0].options.signal.aborted, true, "Reader/request is closed after completion");
});

test("HTTP, CORS, redirects, bad types, oversized bodies and empty images safely fall back", async () => {
  const variants = [
    () => { throw new TypeError("Synthetic CORS/redirect/network failure"); },
    () => new Response(SVG, { status: 403 }),
    () => response("<html/>", { "content-type": "text/html" }),
    () => response(SVG, { "content-length": "65537" }),
    () => response("x".repeat(65537)),
    () => response(""),
    () => new Response(null, { status: 204, headers: { "content-type": "image/png" } }),
  ];
  for (const fetchImpl of variants) {
    const load = createFaviconLoader({ fetchImpl });
    assert.equal(await load(tab()), null);
    assert.equal(await load(tab()), null);
  }
});

test("streamed size is bounded even when Content-Length is missing or false", async () => {
  let cancelled = false;
  const load = createFaviconLoader({ fetchImpl: () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(40000));
      controller.enqueue(new Uint8Array(40000));
    },
    cancel() { cancelled = true; },
  }), { headers: { "content-type": "image/png", "content-length": "1" } }) });
  assert.equal(await load(tab()), null);
  assert.equal(cancelled, true);
});

test("the deadline covers an image body that stalls after response headers", async () => {
  let aborted = false;
  const load = createFaviconLoader({ timeoutMs: 10, fetchImpl: async (_url, { signal }) =>
    new Response(new ReadableStream({
      start(controller) {
        signal.addEventListener("abort", () => {
          aborted = true;
          controller.error(new DOMException("Synthetic timeout", "AbortError"));
        }, { once: true });
      },
    }), { headers: { "content-type": "image/png" } }),
  });
  assert.equal(await load(tab()), null);
  assert.equal(aborted, true);
});

test("memory cache expires successful/failed lookups and evicts old entries", async () => {
  let clock = 0, calls = 0, good = true;
  const load = createFaviconLoader({ now: () => clock, maxEntries: 2, fetchImpl: () => {
    calls++;
    if (!good) throw new TypeError("Synthetic offline");
    return response();
  } });
  await load(tab());
  clock = 299999;
  await load(tab());
  assert.equal(calls, 1);
  clock = 300001;
  await load(tab());
  assert.equal(calls, 2);
  await load(tab(ICON.replace("favicon", "other")));
  await load(tab(ICON.replace("favicon", "third")));
  good = false;
  assert.equal(await load(tab()), null);
  assert.equal(calls, 5);
  clock += 29999;
  assert.equal(await load(tab()), null);
  assert.equal(calls, 5);
  clock += 2;
  good = true;
  assert.ok(await load(tab()));
  assert.equal(calls, 6);
});

test("repeated renders cannot evict pending downloads and bypass the memory/request bound", async () => {
  const pending = [];
  const load = createFaviconLoader({ maxEntries: 2, fetchImpl: () => new Promise(resolve => pending.push(resolve)) });
  const first = load(tab());
  const second = load(tab(ICON.replace("favicon", "second")));
  assert.equal(await load(tab(ICON.replace("favicon", "third"))), null);
  assert.equal(load(tab()), first);
  assert.equal(pending.length, 2);
  for (const resolve of pending) resolve(response());
  assert.ok(await first);
  assert.ok(await second);
});
