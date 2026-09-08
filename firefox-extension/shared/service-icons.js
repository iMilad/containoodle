// Prefer the actual favicon reported by Firefox, not a guessed service drawing.
// This is decorative only, never evidence of account/session identity.
const MAX_BYTES = 64 * 1024;
const IMAGE_TYPE = /^image\/(?:png|jpe?g|gif|webp|x-icon|vnd\.microsoft\.icon|svg\+xml)$/i;
const CONSOLE_HOST = /^(?:[a-z0-9-]+\.)?console\.aws\.amazon\.com$/;
const STUDIO_HOST = /^[a-z0-9-]+\.studio\.[a-z0-9-]+\.sagemaker\.aws$/;

function httpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.port ? url : null;
  } catch { return null; }
}

export function faviconSourceForTab(tab) {
  const value = tab?.favIconUrl;
  if (typeof value !== "string" || !value || value.length > MAX_BYTES * 2) return null;
  // SVG is kept in an <img>, never parsed or inserted into the document.
  // Firefox disables scripts and external resources in SVG image context.
  if (/^data:image\/(?:png|jpe?g|gif|webp|x-icon|vnd\.microsoft\.icon|svg\+xml)(?:;charset=utf-8|;utf8)?(?:;base64)?,/i.test(value)) {
    return { url: value, remote: false };
  }
  // Preserve Firefox's extension-local favicon path for extension tabs.
  if (value.startsWith("moz-extension://")) {
    try {
      const url = new URL(value);
      if (url.hostname && !url.username && !url.password && !url.port) return { url: value, remote: false };
    } catch { /* Not an absolute browser-local image URL. */ }
    return null;
  }
  if (value.length > 2048) return null;
  const page = httpsUrl(tab?.url);
  const icon = httpsUrl(value);
  if (!page || !icon || !(CONSOLE_HOST.test(page.hostname) || STUDIO_HOST.test(page.hostname))) return null;
  // Only browser-reported, static AWS image paths. Never replay sign-in URLs,
  // query strings, arbitrary page hosts, or a third-party favicon service.
  if (!(CONSOLE_HOST.test(icon.hostname) || /^(?:[a-z0-9-]+\.)*awsstatic\.com$/.test(icon.hostname)) ||
      icon.search || !/^\/[a-z0-9/_.@+-]+\.(?:ico|png|jpe?g|gif|webp|svg)$/i.test(icon.pathname)) return null;
  icon.hash = "";
  return { url: icon.href, remote: true };
}

export function createFaviconLoader({ fetchImpl = (...args) => fetch(...args), now = Date.now,
  timeoutMs = 5000, maxEntries = 64 } = {}) {
  // Bounded, sidebar-lifetime memory only; no storage/history/cookie access.
  const cache = new Map();
  async function download(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let reader;
    try {
      const response = await fetchImpl(url, {
        credentials: "omit", referrerPolicy: "no-referrer", redirect: "error",
        mode: "cors", signal: controller.signal,
      });
      const type = response.headers.get("content-type")?.split(";", 1)[0].trim();
      if (!response.ok || !IMAGE_TYPE.test(type || "") ||
          Number(response.headers.get("content-length")) > MAX_BYTES || !response.body) return null;
      reader = response.body.getReader();
      let size = 0;
      const chunks = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_BYTES) return null;
        chunks.push(value);
      }
      if (!size) return null;
      let binary = "";
      for (const chunk of chunks) {
        for (let offset = 0; offset < chunk.length; offset += 4096) {
          binary += String.fromCharCode(...chunk.subarray(offset, offset + 4096));
        }
      }
      return "data:" + type.toLowerCase() + ";base64," + btoa(binary);
    } catch {
      // Offline, CORS, redirect and timeout failures never block a tab.
      return null;
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (reader) await reader.cancel().catch(() => {});
    }
  }
  return function loadFavicon(tab) {
    const source = faviconSourceForTab(tab);
    if (!source) return Promise.resolve(null);
    if (!source.remote) return Promise.resolve(source.url);
    const existing = cache.get(source.url);
    if (existing && existing.expires > now()) return existing.promise;
    cache.delete(source.url);
    while (cache.size >= maxEntries) {
      // Never evict an in-flight request: repeated renders must not bypass the
      // bound by starting another copy of a slow image download.
      const completed = [...cache].find(([, entry]) => entry.expires !== Infinity);
      if (!completed) return Promise.resolve(null);
      cache.delete(completed[0]);
    }
    const entry = { expires: Infinity, promise: null };
    entry.promise = download(source.url).then(value => {
      entry.expires = now() + (value ? 5 * 60_000 : 30_000);
      return value;
    });
    cache.set(source.url, entry);
    return entry.promise;
  };
}
