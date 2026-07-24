/* Orbiting Turnip tab-group display naming.
 *
 * The account's original name remains the source of truth for container
 * identity, sidebar labels, and environment colours. This helper changes only
 * the automatically generated Firefox tab-group title.
 */

export const GROUP_NAME_PATTERN_MAX_LENGTH = 256;
export const GROUP_NAME_REPLACEMENT_MAX_LENGTH = 256;
export const GROUP_NAME_TITLE_MAX_LENGTH = 256;

function assertSafeGroupNamePattern(source) {
  let previousAtom = null;
  let lastWasQuantifier = false;
  let variableQuantifiers = 0;
  let alternatives = 0;

  const reject = (reason) => {
    throw new Error(`Unsafe name regex: ${reason}`);
  };
  const countVariableQuantifier = () => {
    variableQuantifiers += 1;
    if (variableQuantifiers > 2) {
      reject("use at most two variable quantifiers (*, +, ?, or ranged {})");
    }
  };

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === "\\") {
      const escaped = source[index + 1];
      if (/[1-9]/.test(escaped || "") || (escaped === "k" && source[index + 2] === "<")) {
        reject("backreferences are not supported");
      }
      index += escaped === undefined ? 0 : 1;
      previousAtom = "value";
      lastWasQuantifier = false;
      continue;
    }

    if (char === "[") {
      let closed = false;
      for (index += 1; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === "]") {
          closed = true;
          break;
        }
      }
      if (!closed) return; // RegExp compilation below supplies the syntax error.
      previousAtom = "value";
      lastWasQuantifier = false;
      continue;
    }

    if (char === "(") {
      if (source[index + 1] === "?") {
        const groupType = source[index + 2];
        if (groupType === ":") {
          index += 2;
        } else if (groupType === "<") {
          const lookbehindType = source[index + 3];
          if (lookbehindType === "=" || lookbehindType === "!") {
            reject("lookarounds are not supported");
          }
          const nameEnd = source.indexOf(">", index + 3);
          if (nameEnd < 0) return;
          index = nameEnd;
        } else {
          reject("lookarounds and inline modifiers are not supported");
        }
      }
      previousAtom = null;
      lastWasQuantifier = false;
      continue;
    }

    if (char === ")") {
      previousAtom = "group";
      lastWasQuantifier = false;
      continue;
    }

    if (char === "*" || char === "+" || char === "?") {
      if (char === "?" && lastWasQuantifier) continue; // lazy modifier
      if (previousAtom === "group") reject("quantified groups are not supported");
      if (previousAtom) countVariableQuantifier();
      lastWasQuantifier = true;
      continue;
    }

    if (char === "{" && previousAtom) {
      const quantifier = /^\{(\d+)(?:,(\d*))?\}/.exec(source.slice(index));
      if (quantifier) {
        if (previousAtom === "group") reject("quantified groups are not supported");
        const lower = Number(quantifier[1]);
        const hasRange = quantifier[2] !== undefined;
        const upper = hasRange && quantifier[2] !== ""
          ? Number(quantifier[2])
          : lower;
        if (lower > 256 || upper > 256) reject("repetition bounds must not exceed 256");
        if (hasRange && (quantifier[2] === "" || upper !== lower)) {
          countVariableQuantifier();
        }
        index += quantifier[0].length - 1;
        lastWasQuantifier = true;
        continue;
      }
    }

    if (char === "|") {
      alternatives += 1;
      if (alternatives > 4) reject("use at most four alternatives");
      previousAtom = null;
      lastWasQuantifier = false;
      continue;
    }

    if (char === "^" || char === "$") {
      previousAtom = null;
      lastWasQuantifier = false;
      continue;
    }

    previousAtom = "value";
    lastWasQuantifier = false;
  }
}

export function validateGroupNameRule(pattern, replacement) {
  const source = typeof pattern === "string" ? pattern : "";
  const substitute = typeof replacement === "string" ? replacement : "";

  if (source.length > GROUP_NAME_PATTERN_MAX_LENGTH) {
    throw new Error(
      `Invalid name regex: pattern must be at most ${GROUP_NAME_PATTERN_MAX_LENGTH} characters`
    );
  }
  if (substitute.length > GROUP_NAME_REPLACEMENT_MAX_LENGTH) {
    throw new Error(
      `Invalid name replacement: must be at most ${GROUP_NAME_REPLACEMENT_MAX_LENGTH} characters`
    );
  }
  if (source) {
    try {
      new RegExp(source);
    } catch (err) {
      throw new Error(`Invalid name regex: ${err.message}`);
    }
    assertSafeGroupNamePattern(source);
  }

  return { pattern: source, replacement: substitute };
}

export function automaticGroupTitle(originalName, pattern, replacement) {
  const original = typeof originalName === "string" ? originalName : "";
  if (!original) return original;

  try {
    const rule = validateGroupNameRule(pattern, replacement);
    if (!rule.pattern) return original;
    const regex = new RegExp(rule.pattern);
    if (!regex.test(original)) return original;
    const transformed = original.replace(regex, rule.replacement).trim();
    return transformed && transformed.length <= GROUP_NAME_TITLE_MAX_LENGTH
      ? transformed
      : original;
  } catch {
    // Options rejects invalid expressions, but stored configuration may have
    // been written by an older build or manual profile editing.
    return original;
  }
}
