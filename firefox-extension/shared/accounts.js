/* ═══════════════════════════════════════════════════════════════════
   Orbiting Turnip — shared AWS account-field validation.

   Pure, no browser APIs. The field regexes mirror server.py. The
   document parser remains a backend-schema utility for tests/tooling;
   portal shortcuts are pinned from the sidebar, not entered as JSON.
   ═══════════════════════════════════════════════════════════════════ */

export const ACCOUNT_ID_RE = /^\d{12}$/;
export const REGION_RE = /^[a-z]{2}-[a-z]+-\d$/;
export const ROLE_RE = /^[\w+=,.@-]{1,64}$/;

/** Parse and validate an accounts JSON document (same schema as
 *  ~/.aws/accounts.json). Returns { accounts, errors }: on any error
 *  accounts is null and errors holds user-readable messages. */
export function parseAccounts(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    return { accounts: null, errors: [`Invalid JSON: ${e.message}`] };
  }
  if (!Array.isArray(data)) {
    return { accounts: null, errors: ["Top-level value must be an array of accounts"] };
  }
  const errors = [];
  data.forEach((acc, i) => {
    const label = `Entry ${i + 1}`;
    if (typeof acc !== "object" || acc === null || Array.isArray(acc)) {
      errors.push(`${label}: must be an object`);
      return;
    }
    if (!ACCOUNT_ID_RE.test(String(acc.accountId ?? ""))) {
      errors.push(`${label}: accountId must be a 12-digit string`);
    }
    if (typeof acc.accountName !== "string" || !acc.accountName.trim()) {
      errors.push(`${label}: accountName is required`);
    }
    if (acc.role !== undefined && !ROLE_RE.test(String(acc.role))) {
      errors.push(`${label}: invalid role name`);
    }
    if (acc.region !== undefined && !REGION_RE.test(String(acc.region))) {
      errors.push(`${label}: invalid region (expected e.g. eu-west-1)`);
    }
  });
  return errors.length ? { accounts: null, errors } : { accounts: data, errors: [] };
}
