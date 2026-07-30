/* Containoodle portal click interceptor.

   Registered dynamically at document_start only for the configured AWS
   access-portal page after the user grants that host. It observes plain
   left-clicks on documented console shortcut links and reads the displayed
   account name attached to that clicked role. It does not read forms,
   credentials, or unrelated account-list rows. The background validates the
   exact portal URL again before launching anything. */

(() => {
  if (globalThis.__containoodlePortalInterceptorLoaded) return;
  globalThis.__containoodlePortalInterceptorLoaded = true;

  let enabled = false;
  let activeHandoff = null;
  const handoffQueue = [];

  async function refreshState() {
    try {
      const state = await browser.runtime.sendMessage({ type: "portal-interceptor-state" });
      enabled = Boolean(state && state.enabled);
    } catch {
      enabled = false;
    }
  }

  function shortcutUrl(rawUrl) {
    try {
      const candidate = new URL(rawUrl, location.href);
      if (
        candidate.protocol !== "https:" ||
        candidate.username ||
        candidate.password ||
        candidate.origin !== location.origin
      ) return null;
      const candidatePath = candidate.pathname.replace(/\/+$/, "") || "/";
      const currentPath = location.pathname.replace(/\/+$/, "") || "/";
      if (candidatePath !== currentPath) return null;

      const fragment = candidate.hash.startsWith("#") ? candidate.hash.slice(1) : "";
      const queryAt = fragment.indexOf("?");
      if (queryAt < 0 || fragment.slice(0, queryAt).replace(/\/+$/, "") !== "/console") {
        return null;
      }
      const params = new URLSearchParams(fragment.slice(queryAt + 1));
      const accountIds = params.getAll("account_id");
      const roleNames = params.getAll("role_name");
      if (
        accountIds.length !== 1 ||
        roleNames.length !== 1 ||
        !/^\d{12}$/.test(accountIds[0]) ||
        !/^[\w+=,.@-]{1,64}$/.test(roleNames[0])
      ) return null;
      return candidate.href;
    } catch {
      return null;
    }
  }

  function clickedAnchor(event) {
    return event.composedPath().find(
      (node) => node && node.tagName === "A" && typeof node.href === "string"
    );
  }

  function clickedAccountName(anchor) {
    if (!anchor || typeof anchor.closest !== "function") return undefined;
    let row = anchor.closest("tr");
    // The role link is rendered in a row following its account row. Stop at
    // the nearest account cell, with a hard bound in case the portal DOM is
    // malformed or changes shape.
    for (let scanned = 0; row && scanned < 100; scanned += 1) {
      const cell = typeof row.querySelector === "function"
        ? row.querySelector("div[data-testid='account-list-cell']")
        : null;
      if (cell) {
        const rawName = typeof cell.innerText === "string"
          ? cell.innerText
          : cell.textContent;
        if (typeof rawName !== "string") return undefined;
        const name = rawName.trim();
        return name && name.length <= 256 && !/[\u0000-\u001f\u007f]/.test(name)
          ? name
          : undefined;
      }
      row = row.previousElementSibling;
    }
    return undefined;
  }

  function resumeNative(url, disposition) {
    if (disposition === "new-tab") {
      window.open(url, "_blank", "noopener");
    } else {
      location.assign(url);
    }
  }

  function runNextHandoff() {
    if (activeHandoff || handoffQueue.length === 0) return;
    activeHandoff = handoffQueue.shift();
    const { url, disposition, accountName } = activeHandoff;
    browser.runtime.sendMessage({
      type: "portal-shortcut-click",
      url,
      disposition,
      accountName,
    }).then(
      (result) => {
        if (
          !result ||
          (!result.ok && !result.nativeFallback && !result.cancelled)
        ) {
          resumeNative(url, disposition);
        }
      },
      () => resumeNative(url, disposition)
    ).finally(() => {
      activeHandoff = null;
      runNextHandoff();
    });
  }

  function enqueueHandoff(url, disposition, accountName) {
    if (
      (activeHandoff && activeHandoff.url === url && activeHandoff.disposition === disposition) ||
      handoffQueue.some(
        (item) => item.url === url && item.disposition === disposition
      )
    ) return;
    handoffQueue.push({ url, disposition, accountName });
    runNextHandoff();
  }

  window.addEventListener("click", (event) => {
    if (
      !enabled ||
      !event.isTrusted ||
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) return;

    const anchor = clickedAnchor(event);
    if (!anchor || anchor.hasAttribute("download")) return;
    const url = shortcutUrl(anchor.href);
    if (!url) return;
    const target = String(anchor.getAttribute("target") || "").trim().toLowerCase();
    if (target && !["_self", "_top", "_parent", "_blank"].includes(target)) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    const disposition = target === "_blank" ? "new-tab" : "same-tab";
    enqueueHandoff(url, disposition, clickedAccountName(anchor));
  }, true);

  browser.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.config) void refreshState();
  });
  browser.runtime.onMessage.addListener((message) => {
    if (message && message.type === "portal-interceptor-refresh") {
      void refreshState();
    }
  });
  void refreshState();
})();
