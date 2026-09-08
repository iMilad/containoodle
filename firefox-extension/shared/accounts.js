/* ═══════════════════════════════════════════════════════════════════
   Containoodle — shared AWS account-field validation.

   Pure, no browser APIs. The field regexes mirror server.py. The
   document validator also protects helper responses and cached accounts;
   portal shortcuts are pinned from the sidebar, not entered as JSON.
   ═══════════════════════════════════════════════════════════════════ */

export const ACCOUNT_ID_RE = /^[0-9]{12}$/;
// The portal UI deliberately retains its narrower regional endpoint grammar.
export const REGION_RE = /^[a-z]{2}-[a-z]+-\d$/;
export const ACCOUNT_REGION_RE = /^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/;
export const ROLE_RE = /^[A-Za-z0-9_+=,.@-]{1,64}$/;

// Only these fixed, value-free helper diagnostics may reach the account-list
// UI. An authenticated old helper may still return arbitrary exception text;
// never redisplay it, an account ID/name, a local path or a role value.
export function safeAccountsError(payload) {
  if (
    !payload || typeof payload !== "object" || Array.isArray(payload) ||
    Object.keys(payload).length !== 1 || typeof payload.error !== "string"
  ) return null;
  const fixed = new Set([
    "accounts.json not found",
    "accounts.json is invalid",
    "accounts.json could not be read",
    "accounts.json must contain an array of accounts",
  ]);
  if (fixed.has(payload.error)) return payload.error;
  const match = /^accounts\.json entry [1-9][0-9]{0,8}(?: must be an object|: (?:accountId must be a 12-digit string|accountName must be a nonempty string|accountName is too long or contains control characters|accountName contains invalid Unicode|invalid role|invalid region|duplicate accountId))$/.exec(payload.error);
  return match?.[0] === payload.error ? payload.error : null;
}

function matchesEntireField(pattern, value) {
  // JavaScript's $ can match before a final newline; account fields cannot.
  return typeof value === "string" && pattern.exec(value)?.[0] === value;
}

/** Parse and validate an accounts JSON document (same schema as
 *  ~/.aws/accounts.json). Returns { accounts, errors }: on any error
 *  accounts is null and errors holds user-readable messages. */
export function parseAccounts(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    // Engine parse errors can include fragments of the private document.
    return { accounts: null, errors: ["Invalid JSON account document"] };
  }
  return validateAccounts(data);
}

/** Validate parsed helper/cache data without coercing or mutating it. */
export function validateAccounts(data) {
  if (!Array.isArray(data)) {
    return { accounts: null, errors: ["Top-level value must be an array of accounts"] };
  }
  const errors = [];
  const accountIds = new Set();
  for (const [i, acc] of data.entries()) {
    const label = `Entry ${i + 1}`;
    if (typeof acc !== "object" || acc === null || Array.isArray(acc)) {
      errors.push(`${label}: must be an object`);
      continue;
    }
    if (!matchesEntireField(ACCOUNT_ID_RE, acc.accountId)) {
      errors.push(`${label}: accountId must be a 12-digit string`);
    } else if (accountIds.has(acc.accountId)) {
      errors.push(`${label}: duplicate accountId`);
    } else {
      accountIds.add(acc.accountId);
    }
    if (
      typeof acc.accountName !== "string" || !acc.accountName.trim() ||
      [...acc.accountName].length > 256 || /[\u0000-\u001f\u007f]/.test(acc.accountName) ||
      [...acc.accountName].some(char => {
        const point = char.codePointAt(0);
        return point >= 0xd800 && point <= 0xdfff;
      })
    ) {
      errors.push(`${label}: accountName must be nonempty text of at most 256 characters without control characters`);
    }
    if (acc.role !== undefined && !matchesEntireField(ROLE_RE, acc.role)) {
      errors.push(`${label}: invalid role name`);
    }
    if (acc.region !== undefined && !matchesEntireField(ACCOUNT_REGION_RE, acc.region)) {
      errors.push(`${label}: invalid region (expected e.g. eu-west-1)`);
    }
  }
  return errors.length ? { accounts: null, errors } : { accounts: data, errors: [] };
}
