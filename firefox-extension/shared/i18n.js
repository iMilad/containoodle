/* English is the shipped default. Missing/unsupported locale APIs must never
 * prevent setup, account rendering, or a security permission action. */

export function message(key, fallback, substitutions = []) {
  const values = (Array.isArray(substitutions) ? substitutions : [substitutions])
    .map((value) => String(value));
  try {
    const translated = globalThis.browser?.i18n?.getMessage(key, values);
    if (typeof translated === "string" && translated) return translated;
  } catch {
    // A missing translation is cosmetic, not a reason to block the extension.
  }
  return String(fallback).replace(/\$\$|\$([1-9])/g, (match, index) => {
    if (match === "$$") return "$";
    return values[Number(index) - 1] ?? match;
  });
}

// Rich messages use numbered placeholders for existing, trusted markup. The
// translation is always text: it cannot add HTML, attributes, links or scripts.
// Slots may move, but must occur exactly once so controls/code cannot disappear.
function localizeText(node) {
  const key = node.getAttribute("data-i18n");
  const slots = [...(node.children || [])];
  if (!slots.length) {
    node.textContent = message(key, node.textContent);
    return;
  }
  if (slots.some((slot, index) =>
    slot.getAttribute("data-i18n-slot") !== String(index + 1)
  )) return;

  const markers = slots.map((_, index) => `[[containoodle-slot-${index + 1}]]`);
  const fallback = [...node.childNodes].map((child) => {
    const index = slots.indexOf(child);
    return index < 0 ? child.textContent.replace(/\$/g, "$$$$") : `$${index + 1}`;
  }).join("");
  const localized = message(key, fallback, markers);
  if (markers.some((marker) => localized.split(marker).length !== 2)) return;
  const fragments = localized.split(/(\[\[containoodle-slot-[1-9]\]\])/g);
  if (fragments.some((part) =>
    part.startsWith("[[containoodle-slot-") && !markers.includes(part)
  )) return;
  const doc = node.ownerDocument;
  if (!doc?.createTextNode || !node.replaceChildren) return;
  node.replaceChildren(...fragments.map((part) => {
    const index = markers.indexOf(part);
    return index < 0 ? doc.createTextNode(part) : slots[index];
  }));
}

export function localizeDocument(root = globalThis.document) {
  if (!root?.querySelectorAll) return;
  for (const node of root.querySelectorAll("[data-i18n]")) localizeText(node);
  for (const attribute of ["title", "placeholder", "aria-label"]) {
    for (const node of root.querySelectorAll(`[data-i18n-${attribute}]`)) {
      node.setAttribute(attribute, message(
        node.getAttribute(`data-i18n-${attribute}`),
        node.getAttribute(attribute) || "",
      ));
    }
  }
  // Use catalog metadata, not the browser UI locale: the selected UI locale
  // might be unsupported and resolve to our English fallback messages.
  const locale = message("locale_code", "en");
  const direction = message("locale_direction", "ltr");
  if (root.documentElement) {
    root.documentElement.lang = locale.replace(/_/g, "-");
    root.documentElement.dir = direction === "rtl" ? "rtl" : "ltr";
  }
}
