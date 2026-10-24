/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import zxcvbn from "resource:///modules/zxcvbn.mjs";

/**
 * Password policy tiers for a Primary Password, as data rather than as a
 * branch inside a dialog.
 *
 * The names and the arithmetic are the ones `workbench-development`'s
 * `password_validation.py` uses, so one password-strength vocabulary exists
 * across these projects. The tiers:
 *
 *   low      6 characters,  no character classes,  strength score 0
 *   medium   8 characters,  upper + lower + digit, strength score 2
 *   high    10 characters,  all four classes,      strength score 3
 *   custom   the same six fields, caller-supplied
 *
 * This file lives in toolkit because the dialog that consumes it does. It has
 * no callers in Firefox: the preference that selects a tier is unset by
 * default, and an unset preference means "no policy", which is exactly the
 * behaviour the dialog had before this file existed. Thunderbird sets the
 * preference (design 12.6 chooses `high`), and nothing here knows or cares
 * which application is asking.
 */

/**
 * The preference holding the tier name. Read when the dialog opens, so a
 * policy pushed by `Preferences` applies to the next change without a
 * restart.
 */
export const TIER_PREF = "security.primary_password.policy.tier";

/** The preference holding the custom tier's fields, as a JSON string. */
export const CUSTOM_PREF = "security.primary_password.policy.custom";

/**
 * The tiers, with the six fields the design asks for. `minStrength` is the
 * zxcvbn score, 0-4, and it *is* enforced: zxcvbn 4.4.2 is vendored at
 * `third_party/js/zxcvbn/` and imported above.
 *
 * @type {Record<string, {minLength: number, requireUppercase: boolean,
 *   requireLowercase: boolean, requireDigit: boolean,
 *   requireSpecial: boolean, minStrength: number}>}
 */
export const TIERS = {
  low: {
    minLength: 6,
    requireUppercase: false,
    requireLowercase: false,
    requireDigit: false,
    requireSpecial: false,
    minStrength: 0,
  },
  medium: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecial: false,
    minStrength: 2,
  },
  high: {
    minLength: 10,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecial: true,
    minStrength: 3,
  },
  custom: {
    minLength: 6,
    requireUppercase: false,
    requireLowercase: false,
    requireDigit: false,
    requireSpecial: false,
    minStrength: 0,
  },
};

/** Every rule a password can fail, in the order a message should list them. */
export const RULES = [
  "min-length",
  "uppercase",
  "lowercase",
  "digit",
  "special",
  "strength",
];

/**
 * The score a password actually earns, 0-4.
 *
 * zxcvbn is deliberately advisory in Firefox's hands elsewhere, but here it
 * gates a decision -- so the failure modes are handled rather than assumed:
 * an estimator that throws, or returns something that is not a score, must not
 * silently pass a weak password and must not block a strong one.
 *
 * @param {string} password
 * @returns {{score: number|null, error: string|null}} `score` is null when the
 *   estimator could not be used; `error` says why.
 */
export function estimateScore(password) {
  try {
    const result = zxcvbn(password);
    if (
      !result ||
      !Number.isInteger(result.score) ||
      result.score < 0 ||
      result.score > 4
    ) {
      return { score: null, error: "estimator returned no usable score" };
    }
    return { score: result.score, error: null };
  } catch (ex) {
    return { score: null, error: String(ex) };
  }
}

const RE_UPPER = /[A-Z]/;
const RE_LOWER = /[a-z]/;
const RE_DIGIT = /\d/;
const RE_SPECIAL = /[^a-zA-Z0-9]/;

/**
 * Resolves a tier name and custom fields into one rule set.
 *
 * An unknown tier name falls back to `low` rather than to `high`: a
 * misspelling in a policy file should not lock every user out of changing a
 * password, and `low` is the permissive end. The caller can distinguish the
 * two cases because `resolveTier()` reports which name it actually used.
 *
 * @param {string} name
 * @param {object} [custom] Fields for the `custom` tier.
 * @returns {{name: string, requested: string,
 *   rules: object, unknownTier: boolean}}
 */
export function resolveTier(name, custom) {
  const requested = typeof name === "string" ? name.trim().toLowerCase() : "";
  if (requested === "custom") {
    return {
      name: "custom",
      requested,
      rules: {
        ...TIERS.custom,
        ...normaliseCustom(custom),
      },
      unknownTier: false,
    };
  }
  if (Object.hasOwn(TIERS, requested) && requested !== "custom") {
    return {
      name: requested,
      requested,
      rules: { ...TIERS[requested] },
      unknownTier: false,
    };
  }
  return {
    name: "low",
    requested,
    rules: { ...TIERS.low },
    unknownTier: Boolean(requested),
  };
}

/**
 * Coerces custom fields, ignoring anything unrecognised.
 *
 * @param {object} custom
 * @returns {object} A partial rule set.
 */
function normaliseCustom(custom) {
  if (!custom || typeof custom !== "object") {
    return {};
  }
  const out = {};
  const len = Number(custom.minLength);
  if (Number.isFinite(len) && len >= 0) {
    out.minLength = Math.trunc(len);
  }
  for (const key of [
    "requireUppercase",
    "requireLowercase",
    "requireDigit",
    "requireSpecial",
  ]) {
    if (typeof custom[key] === "boolean") {
      out[key] = custom[key];
    }
  }
  const strength = Number(custom.minStrength);
  if (Number.isFinite(strength) && strength >= 0 && strength <= 4) {
    out.minStrength = Math.trunc(strength);
  }
  return out;
}

/**
 * Evaluates a password against a resolved rule set.
 *
 * An empty password is not evaluated: clearing the Primary Password is a
 * deliberate action the dialog's own rules govern (`removeMasterPassword`),
 * and applying a length minimum to it would make the password impossible to
 * remove.
 *
 * @param {string} password
 * @param {object} rules From `resolveTier()`.
 * @param {Function} [estimator] Injected for tests; defaults to zxcvbn via
 *   `estimateScore()`.
 * @returns {string[]} Failing rule names, empty when the password is
 *   acceptable.
 */
export function failingRules(password, rules, estimator = estimateScore) {
  if (!password) {
    return [];
  }
  const failures = [];
  if (password.length < rules.minLength) {
    failures.push("min-length");
  }
  if (rules.requireUppercase && !RE_UPPER.test(password)) {
    failures.push("uppercase");
  }
  if (rules.requireLowercase && !RE_LOWER.test(password)) {
    failures.push("lowercase");
  }
  if (rules.requireDigit && !RE_DIGIT.test(password)) {
    failures.push("digit");
  }
  if (rules.requireSpecial && !RE_SPECIAL.test(password)) {
    failures.push("special");
  }
  // The score is checked last, and only when the tier asks for one. An
  // estimator failure is reported as a failure rather than passed: a
  // requirement that cannot be checked has not been met, and silently
  // accepting would tell the user their password cleared a bar nobody
  // measured. It is *reported*, not thrown, so the dialog can say which rule
  // and the user is never left with an unresponsive button.
  if (rules.minStrength > 0) {
    const { score } = estimator(password);
    // Validated here, not only in `estimateScore()`: this function accepts an
    // injected estimator, and a value outside 0-4 is not a score. Trusting it
    // would let one bad return turn a requirement into a pass.
    const usable = Number.isInteger(score) && score >= 0 && score <= 4;
    if (!usable || score < rules.minStrength) {
      failures.push("strength");
    }
  }
  return failures;
}
