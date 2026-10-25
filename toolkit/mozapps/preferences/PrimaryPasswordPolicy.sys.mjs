/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** Cached namespace for the vendored estimator, filled on first use. */
var gZxcvbn = null;

const ESTIMATOR_URL = "resource://gre/modules/zxcvbn.mjs";

/**
 * The estimator callable, loaded on first use.
 *
 * `ChromeUtils.importESModule` rather than a static `import` or
 * `defineESModuleGetters`:
 *
 *  - a static import of a `resource:///modules/` URL is rejected by
 *    `mozilla/no-browser-refs-in-toolkit`, because toolkit also runs where
 *    Firefox's module tree is absent;
 *  - and `defineESModuleGetters` declares the property but leaves it
 *    `undefined` here -- measured 2026-10-25 with a probe inside this module,
 *    the same silent failure seen from `RNP.sys.mjs` while a direct import of
 *    the identical URL worked.
 *
 * A failed load is remembered as `null` so this is attempted once, not on
 * every keystroke.
 *
 * @returns {Function|null}
 */
function estimatorFunction() {
  if (gZxcvbn !== null) {
    return gZxcvbn;
  }
  try {
    const ns = ChromeUtils.importESModule(ESTIMATOR_URL);
    gZxcvbn = typeof ns.default === "function" ? ns.default : null;
  } catch (ex) {
    console.error("Primary Password policy: estimator unavailable", ex);
    gZxcvbn = null;
  }
  return gZxcvbn;
}

/**
 * Loads the estimator, if it is not already available.
 *
 * Called once, from the dialog's init. Returns false rather than throwing, so a
 * missing module degrades to "no score" instead of breaking the dialog.
 *
 * @returns {boolean} true when the estimator can be used.
 */
export function loadEstimator() {
  return typeof estimatorFunction() === "function";
}

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

/**
 * Every rule a password can fail, in the order a message should list them,
 * with the Fluent id that names it.
 *
 * Data, not a branch: `changemp.js` renders whatever is in this list, so a
 * rule can be added here and its string added to the FTL without touching the
 * dialog. That is the same shape as the tier table above, for the same reason.
 */
export const RULES = [
  { id: "min-length", l10n: "primary-password-policy-min-length" },
  { id: "uppercase", l10n: "primary-password-policy-uppercase" },
  { id: "lowercase", l10n: "primary-password-policy-lowercase" },
  { id: "digit", l10n: "primary-password-policy-digit" },
  { id: "special", l10n: "primary-password-policy-special" },
  { id: "strength", l10n: "primary-password-policy-strength" },
];

/** Rule ids alone, for callers that only need to know which failed. */
export const RULE_IDS = RULES.map(r => r.id);

/**
 * The Fluent id that names a rule.
 *
 * @param {string} id
 * @returns {string|null}
 */
export function ruleL10nId(id) {
  return RULES.find(r => r.id === id)?.l10n ?? null;
}

/**
 * zxcvbn's `pattern` values, mapped to a Fluent id explaining that pattern.
 *
 * **Mapped from the structured field, not from the English `warning` string.**
 * The warning is prose inside a vendored library: it is not translated, it
 * changes when the library is upgraded, and matching on it would silently
 * produce nothing the day a wording changes. `pattern` is a closed set the
 * library documents and its own code switches on, so it is a contract.
 *
 * `bruteforce` is the catch-all for characters that matched no pattern -- it
 * means "nothing specific to say, it was simply short or unusual", and it is
 * the weakest message of the set, which is why it is last.
 */
export const PATTERN_L10N = {
  dictionary: "primary-password-policy-reason-dictionary",
  spatial: "primary-password-policy-reason-spatial",
  repeat: "primary-password-policy-reason-repeat",
  sequence: "primary-password-policy-reason-sequence",
  date: "primary-password-policy-reason-date",
  regex: "primary-password-policy-reason-date",
  bruteforce: "primary-password-policy-reason-bruteforce",
};

/**
 * The pattern that best explains a low score.
 *
 * Chosen by the length of the matched token, not by order: the longest match
 * is what made the password guessable, so `Password1!` reports the dictionary
 * hit rather than the three characters of brute force after it.
 *
 * @param {object} result A zxcvbn result.
 * @returns {string|null} A Fluent id, or null when nothing was matched.
 */
export function explainingPatternL10nId(result) {
  const seq = result?.sequence;
  if (!Array.isArray(seq) || !seq.length) {
    return null;
  }
  let best = null;
  for (const match of seq) {
    const l10n = PATTERN_L10N[match?.pattern];
    if (!l10n) {
      continue;
    }
    // `bruteforce` only stands in when nothing more specific matched, so it is
    // held to a lower priority than any real pattern of the same length.
    const weight =
      match.pattern === "bruteforce" ? -1 : (match.token?.length ?? 0);
    if (!best || weight > best.weight) {
      best = { l10n, weight };
    }
  }
  return best?.l10n ?? null;
}

/**
 * The score a password actually earns, 0-4, and what made it that score.
 *
 * zxcvbn is deliberately advisory in Firefox's hands elsewhere, but here it
 * gates a decision -- so the failure modes are handled rather than assumed:
 * an estimator that throws, or returns something that is not a score, must not
 * silently pass a weak password and must not block a strong one.
 *
 * `reasonL10n` is included so a caller can say *why* rather than only that the
 * password was weak, which is the difference between a message that teaches
 * and one that only refuses. It is null when no explanation is available,
 * including whenever the score is unusable.
 *
 * @param {string} password
 * @returns {{score: number|null, error: string|null,
 *   reasonL10n: string|null}} `score` is null when the estimator could not be
 *   used; `error` says why.
 */
export function estimateScore(password) {
  const estimate = estimatorFunction();
  if (!estimate) {
    return {
      score: null,
      error: "estimator not loaded",
      reasonL10n: null,
    };
  }
  try {
    const result = estimate(password);
    if (
      !result ||
      !Number.isInteger(result.score) ||
      result.score < 0 ||
      result.score > 4
    ) {
      return {
        score: null,
        error: "estimator returned no usable score",
        reasonL10n: null,
      };
    }
    return {
      score: result.score,
      error: null,
      reasonL10n: explainingPatternL10nId(result),
    };
  } catch (ex) {
    return { score: null, error: String(ex), reasonL10n: null };
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
 * Scores an existing password and says whether it would satisfy the policy, as
 * **advice only**.
 *
 * Item 59's requirement, and the shape of the function is the requirement: the
 * result is descriptive, and nothing in this module refuses anything on it. An
 * account whose password was accepted last year must still open today, so a
 * caller may show this and may not act on it.
 *
 * The tiers and the estimator are here already, so the question belongs here
 * rather than in a caller -- and this keeps the answer inside the toolkit
 * namespace, which is the only one a toolkit file may reach.
 *
 * Never throws: advice that can break a dialog is worse than no advice.
 *
 * @param {string} password
 * @param {string} tierName The configured tier, empty for no policy.
 * @param {object} [custom] Fields for the `custom` tier.
 * @returns {{scored: boolean, score: number|null, belowPolicy: boolean,
 *   tier: string|null, reasonL10n: string|null}} `scored` is false when there
 *   is no policy, no plaintext, or no usable score.
 */
export function scoreExistingPassword(password, tierName, custom) {
  const nothing = {
    scored: false,
    score: null,
    belowPolicy: false,
    tier: null,
    reasonL10n: null,
  };
  if (!password || !tierName) {
    return nothing;
  }
  const resolved = resolveTier(tierName, custom);
  const { score, reasonL10n } = estimateScore(password);
  if (score === null) {
    // Nothing trustworthy to say, so say nothing.
    return { ...nothing, tier: resolved.name };
  }
  return {
    scored: true,
    score,
    belowPolicy: score < resolved.rules.minStrength,
    tier: resolved.name,
    reasonL10n,
  };
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
