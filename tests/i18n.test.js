import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { message, localizeDocument } from "../firefox-extension/shared/i18n.js";

const catalog = JSON.parse(await readFile(
  new URL("../firefox-extension/_locales/en/messages.json", import.meta.url),
  "utf8",
));

test("public display name adds its purpose while preserving the extension identity", async () => {
  const manifest = JSON.parse(await readFile(
    new URL("../firefox-extension/manifest.json", import.meta.url), "utf8",
  ));
  assert.equal(manifest.name, "Containoodle — AWS Console Containers");
  assert.equal(manifest.browser_specific_settings.gecko.id,
    "{7da5f34e-08f0-4e4e-be7f-7b9b66ab7f60}");
  assert.equal(manifest.sidebar_action.default_title, "Containoodle");
});

function catalogMessage(key, substitutions = []) {
  const entry = catalog[key];
  if (!entry) return "";
  return entry.message.replace(/\$\$|\$([A-Za-z0-9_]+)\$/g, (token, name) => {
    if (token === "$$") return "$";
    const slot = entry.placeholders?.[name.toLowerCase()]?.content;
    assert.match(slot, /^\$[1-9]$/);
    return substitutions[Number(slot.slice(1)) - 1] ?? "";
  });
}

async function withI18n(i18n, run) {
  const original = Object.getOwnPropertyDescriptor(globalThis, "browser");
  globalThis.browser = i18n ? { i18n } : undefined;
  try {
    await run();
  } finally {
    if (original) Object.defineProperty(globalThis, "browser", original);
    else delete globalThis.browser;
  }
}

class TextNode {
  constructor(text) { this.textContent = text; }
}

class Element {
  constructor(attributes = {}, children = []) {
    this.attributes = new Map(Object.entries(attributes));
    this.childNodes = children;
    this.ownerDocument = { createTextNode: (text) => new TextNode(text) };
  }
  get children() { return this.childNodes.filter((node) => node instanceof Element); }
  get textContent() { return this.childNodes.map((node) => node.textContent).join(""); }
  set textContent(value) { this.childNodes = [new TextNode(value)]; }
  getAttribute(key) { return this.attributes.get(key); }
  setAttribute(key, value) { this.attributes.set(key, value); }
  replaceChildren(...nodes) { this.childNodes = nodes; }
}

function documentFor(...nodes) {
  return {
    documentElement: { lang: "en", dir: "ltr" },
    querySelectorAll(selector) {
      const attribute = selector.slice(1, -1);
      return nodes.filter((node) => node.attributes.has(attribute));
    },
  };
}

test("native locale lookup receives string substitutions and safely falls back", async () => {
  await withI18n({
    getMessage(key, substitutions) {
      assert.equal(key, "synthetic_message");
      assert.deepEqual(substitutions, ["7", "<synthetic-account>"]);
      return "TEST-LOCALIZED <synthetic-account>: 7";
    },
  }, () => {
    assert.equal(message("synthetic_message", "$1: $2", [7, "<synthetic-account>"]),
      "TEST-LOCALIZED <synthetic-account>: 7");
  });
  for (const api of [undefined, {}, { getMessage: () => "" }, {
    getMessage() { throw new Error("synthetic unavailable locale"); },
  }]) {
    await withI18n(api, () => {
      assert.equal(message("missing", "$2 / $1 / $$ / $3", [7, "$1"]), "$1 / 7 / $ / $3");
      assert.equal(message("missing", "$1", "synthetic"), "synthetic");
    });
  }
});

test("document localization changes only text and permitted text attributes", async () => {
  const node = new Element({
    "data-i18n": "synthetic_text",
    "data-i18n-title": "synthetic_title",
    "data-i18n-placeholder": "synthetic_placeholder",
    "data-i18n-aria-label": "synthetic_accessible",
    "title": "English title",
    "placeholder": "English placeholder",
    "aria-label": "English accessible label",
    "id": "unchanged-control",
    "value": "__CONTAINOODLE_TEST_ACCOUNT__",
  }, [new TextNode("English label")]);
  const doc = documentFor(node);
  const translated = {
    synthetic_text: "<img src=x onerror=alert(1)>",
    synthetic_title: "TEST title",
    synthetic_placeholder: "TEST placeholder",
    synthetic_accessible: "TEST accessible",
    locale_code: "test_LOCALE",
    locale_direction: "rtl",
  };
  await withI18n({ getMessage: (key) => translated[key] || "" }, () => localizeDocument(doc));
  assert.equal(node.textContent, translated.synthetic_text);
  assert.equal(node.children.length, 0, "translation must not create HTML");
  assert.equal(node.getAttribute("id"), "unchanged-control");
  assert.equal(node.getAttribute("value"), "__CONTAINOODLE_TEST_ACCOUNT__");
  assert.equal(node.getAttribute("title"), "TEST title");
  assert.equal(node.getAttribute("placeholder"), "TEST placeholder");
  assert.equal(node.getAttribute("aria-label"), "TEST accessible");
  assert.equal(doc.documentElement.lang, "test-LOCALE");
  assert.equal(doc.documentElement.dir, "rtl");
});

test("rich text localization can reorder trusted slots without recreating them", async () => {
  const code = new Element({ "data-i18n-slot": "1" }, [new TextNode("$1")]);
  const strong = new Element({ "data-i18n-slot": "2" }, [new TextNode("Save & test")]);
  code.listenerIdentity = () => {};
  const node = new Element({ "data-i18n": "synthetic_rich" }, [
    new TextNode("Use "), code, new TextNode(" before "), strong, new TextNode("."),
  ]);
  await withI18n({ getMessage: (key, slots) => key === "synthetic_rich"
    ? `${slots[1]} <script>literal text</script> ${slots[0]}` : "" }, () => {
    localizeDocument(documentFor(node));
  });
  assert.deepEqual(node.children, [strong, code]);
  assert.equal(node.textContent, "Save & test <script>literal text</script> $1");
  assert.equal(typeof code.listenerIdentity, "function");
});

test("invalid rich translations cannot omit or duplicate markup slots", async () => {
  for (const translated of ["No slot", "$1 $1", "$1 $2"]) {
    const code = new Element({ "data-i18n-slot": "1" }, [new TextNode("server.py")]);
    const node = new Element({ "data-i18n": "synthetic_rich" }, [new TextNode("Run "), code]);
    await withI18n({ getMessage: (key, slots) => key === "synthetic_rich"
      ? translated.replaceAll("$1", slots[0]).replaceAll("$2", "[[containoodle-slot-2]]") : "" }, () => {
      localizeDocument(documentFor(node));
    });
    assert.equal(node.textContent, "Run server.py");
    assert.deepEqual(node.children, [code]);
  }
});

test("English fallback preserves rich command and regex literals without browser APIs", async () => {
  const code = new Element({ "data-i18n-slot": "1" }, [new TextNode("$1 / $<name>")]);
  const node = new Element({ "data-i18n": "missing" }, [new TextNode("Use $ and "), code]);
  const doc = documentFor(node);
  await withI18n(undefined, () => {
    localizeDocument(doc);
    localizeDocument();
  });
  assert.equal(node.textContent, "Use $ and $1 / $<name>");
  assert.equal(node.children[0], code);
  assert.equal(doc.documentElement.lang, "en");
  assert.equal(doc.documentElement.dir, "ltr");
});

test("every static, dynamic and manifest locale key exists and English matches dynamic fallbacks", async () => {
  const used = new Set(["locale_code", "locale_direction"]);
  for (const file of ["options/options.html", "sidebar/sidebar.html", "manifest.json"]) {
    const source = await readFile(new URL(`../firefox-extension/${file}`, import.meta.url), "utf8");
    for (const match of source.matchAll(/data-i18n(?:-title|-placeholder|-aria-label)?="([a-z0-9_]+)"|__MSG_([a-z0-9_]+)__/g)) {
      const key = match[1] || match[2];
      assert.ok(catalog[key], `${file}: missing ${key}`);
      used.add(key);
    }
  }
  const string = '"(?:[^"\\\\]|\\\\.)*"';
  const calls = new RegExp(`\\bt\\(\\s*(${string})\\s*,\\s*(${string})`, "g");
  for (const file of ["options/options.js", "sidebar/sidebar.js"]) {
    const source = await readFile(new URL(`../firefox-extension/${file}`, import.meta.url), "utf8");
    for (const match of source.matchAll(calls)) {
      const key = JSON.parse(match[1]);
      const fallback = JSON.parse(match[2]);
      const substitutions = ["SYNTHETIC_1", "SYNTHETIC_2", "SYNTHETIC_3"];
      assert.ok(catalog[key], `${file}: missing ${key}`);
      used.add(key);
      await withI18n(undefined, () => {
        assert.equal(catalogMessage(key, substitutions), message(key, fallback, substitutions), key);
      });
    }
  }
  assert.equal(used.size, Object.keys(catalog).length, "no orphaned English messages");
  assert.ok(used.size >= 200, "Options/sidebar interface must remain catalog-ready");
  for (const [key, entry] of Object.entries(catalog)) {
    assert.match(key, /^[a-z0-9_]+$/);
    assert.ok(entry.message && entry.description, `${key}: message and translator context required`);
    for (const slot of Object.values(entry.placeholders || {})) assert.match(slot.content, /^\$[1-9]$/);
  }
});

test("English catalog exactly preserves static labels, rich prose and accessible attributes", async () => {
  const plain = (html) => html.replace(/<[^>]*>/g, "")
    .replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"').replaceAll("&#39;", "'");
  let checked = 0;
  for (const file of ["options/options.html", "sidebar/sidebar.html"]) {
    const html = await readFile(new URL(`../firefox-extension/${file}`, import.meta.url), "utf8");
    for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bdata-i18n="([a-z0-9_]+)"[^>]*>/g)) {
      const end = html.indexOf(`</${match[1]}>`, match.index + match[0].length);
      assert.ok(end >= 0, `${file}: translated element must have closing tag`);
      const content = html.slice(match.index + match[0].length, end);
      const slots = [];
      for (const slot of content.matchAll(/<(code|strong)\b[^>]*data-i18n-slot="([1-9])"[^>]*>([\s\S]*?)<\/\1>/g)) {
        slots[Number(slot[2]) - 1] = plain(slot[3]);
      }
      assert.equal(catalogMessage(match[2], slots), plain(content), `${file}: ${match[2]}`);
      checked += 1;
    }
    for (const tag of html.matchAll(/<[a-z][a-z0-9]*\b[^>]*>/g)) {
      for (const attribute of ["title", "placeholder", "aria-label"]) {
        const key = tag[0].match(new RegExp(`data-i18n-${attribute}="([a-z0-9_]+)"`))?.[1];
        if (!key) continue;
        const fallback = tag[0].match(new RegExp(`\\s${attribute}="([^"]*)"`))?.[1];
        assert.equal(catalogMessage(key), plain(fallback), `${file}: ${attribute}`);
        checked += 1;
      }
    }
  }
  assert.equal(checked, 95, "all static interface strings and attributes must retain English copy");
});

test("sidebar purpose subtitle is localized below the unchanged brand and version", async () => {
  const html = await readFile(new URL("../firefox-extension/sidebar/sidebar.html", import.meta.url), "utf8");
  assert.match(html, /class="brand-name-row"[\s\S]*?<span>Containoodle<\/span>[\s\S]*?id="brand-version"[\s\S]*?class="brand-subtitle" data-i18n="ui_aws_console_containers">AWS Console Containers<\/span>/);
  assert.equal(catalog.ui_aws_console_containers.message, "AWS Console Containers");
});
