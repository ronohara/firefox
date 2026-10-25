/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// `PrimaryPasswordPolicy` is bound to the module *namespace*, not destructured.
// That distinction is the bug this code had: the module exports individual
// functions and constants (`TIER_PREF`, `RULES`, `resolveTier`, ...) and no
// member called `PrimaryPasswordPolicy`, so `{ PrimaryPasswordPolicy }` was
// `undefined` and every policy read threw. `ProfileKekPassword` does export a
// member of that name, so it is destructured.
var PrimaryPasswordPolicy = ChromeUtils.importESModule(
  "resource://gre/modules/PrimaryPasswordPolicy.sys.mjs"
);
var { ProfileKekPassword } = ChromeUtils.importESModule(
  "resource://gre/modules/ProfileKekPassword.sys.mjs"
);

/**
 * The rule set in force for this dialog, resolved once when it opens.
 *
 * Read at open rather than at module load so a policy pushed by the
 * `Preferences` enterprise policy applies to the next change without a
 * restart. An unset tier preference means no policy: `failingRules()` is not
 * consulted and the dialog behaves exactly as it did before this existed,
 * which is what keeps Firefox unaffected.
 *
 * @type {{name: string, rules: object}|null}
 */
var gPolicy = null;

/**
 * Pre-formatted policy strings, filled once when the dialog opens.
 *
 * Rendering happens on every keystroke, and `document.l10n.formatValues()`
 * returns a promise. Awaiting it there would make the accept button's state
 * lag the typing, so the strings are formatted once at open and the keystroke
 * path stays synchronous. A miss falls back to the rule id rather than
 * blocking -- an untranslated rule should read oddly, not hang the dialog.
 *
 * @type {Map<string, string>}
 */
var gPolicyText = new Map();

/**
 * Formats every rule and reason string the dialog can show.
 *
 * @returns {Promise<void>}
 */
async function loadPolicyText() {
  const ids = [
    ...PrimaryPasswordPolicy.RULES.map(r => r.l10n),
    ...Object.values(PrimaryPasswordPolicy.PATTERN_L10N),
  ];
  const unique = [...new Set(ids)];
  const min = gPolicy?.rules?.minLength ?? 0;
  const results = await document.l10n.formatValues(
    unique.map(id =>
      id === "primary-password-policy-min-length"
        ? { id, args: { min } }
        : { id }
    )
  );
  gPolicyText = new Map(unique.map((id, i) => [id, results[i]]));
}

/**
 * Reads the tier preference and resolves it.
 *
 * @returns {{name: string, rules: object}|null} null when no policy is set.
 */
/**
 * The custom tier's fields, as stored by the Preferences policy.
 *
 * @returns {object|null} null when unset or not JSON.
 */
function readCustomPolicy() {
  const raw = Services.prefs.getStringPref(
    PrimaryPasswordPolicy.CUSTOM_PREF,
    ""
  );
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (ex) {
    console.error("Primary Password policy: custom tier is not JSON", ex);
    return null;
  }
}

function readPolicy() {
  const tier = Services.prefs.getStringPref(
    PrimaryPasswordPolicy.TIER_PREF,
    ""
  );
  if (!tier) {
    return null;
  }
  const resolved = PrimaryPasswordPolicy.resolveTier(
    tier,
    readCustomPolicy()
  );
  if (resolved.unknownTier) {
    console.warn(
      `Primary Password policy: unknown tier "${resolved.requested}", ` +
        `falling back to "${resolved.name}"`
    );
  }
  return { name: resolved.name, rules: resolved.rules };
}

function init() {
  // A policy is an optional extra, so failing to read one must not stop the
  // dialog working. It did: an exception here skipped every listener below,
  // and the dialog then opened, ignored accept, and closed as though it had
  // saved -- a password change that silently did nothing.
  try {
    gPolicy = readPolicy();
  } catch (ex) {
    gPolicy = null;
    console.error("Primary Password policy: could not be read", ex);
  }
  // Formatting is async but nothing is typed yet, so the keystroke path below
  // can read the cache synchronously. A failure leaves the map empty and the
  // dialog falls back to rule ids.
  loadPolicyText().catch(ex =>
    console.error("Primary Password policy: strings unavailable", ex)
  );
  process();
  document.addEventListener("dialogaccept", setPassword);
  document.getElementById("pw1").addEventListener("input", () => {
    setPasswordStrength();
    checkPasswords();
  });
  document.getElementById("pw2").addEventListener("input", checkPasswords);
}

function process() {
  // If the token doesn't have a password, don't use the old password box.
  // Otherwise, do.
  let token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
  let oldpwbox = document.getElementById("oldpw");
  let msgBox = document.getElementById("message");
  if (!token.hasPassword) {
    oldpwbox.hidden = true;
    msgBox.hidden = false;
    // Select first password field
    document.getElementById("pw1").focus();
  } else {
    // Select old password field
    oldpwbox.hidden = false;
    msgBox.hidden = true;
    oldpwbox.focus();
  }

  if (
    !token.hasPassword &&
    !Services.policies.isAllowed("removeMasterPassword")
  ) {
    document.getElementById("admin").hidden = false;
  }

  checkPasswords();
}

async function createAlert(titleL10nId, messageL10nId) {
  const [title, message] = await document.l10n.formatValues([
    { id: titleL10nId },
    { id: messageL10nId },
  ]);
  Services.prompt.alert(window, title, message);
}

async function setPassword(event) {
  event.preventDefault();

  let token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );

  let oldpwbox = document.getElementById("oldpw");
  let pw1 = document.getElementById("pw1");
  if (pw1.value == "") {
    const fipsUtils = Cc["@mozilla.org/security/fipsutils;1"].getService(
      Ci.nsIFIPSUtils
    );
    if (fipsUtils.isFIPSEnabled) {
      // empty passwords are not allowed in FIPS mode
      createAlert("pw-change-failed-title", "pp-change2empty-in-fips-mode");
      return;
    }
  }

  let kekMoved = false;
  try {
    // token.changePassword can't be reverted. Update lockstore KEK first, if
    // it fails, it rolls changes back, so failure leaves a working state.
    // Without a KEK the update would create one from an old password nothing
    // here can verify, so that is left to the next startup, which checks it
    // against the token first.
    if (!token.hasPassword || (await ProfileKekPassword.exists())) {
      await ProfileKekPassword.update(oldpwbox.value, pw1.value);
      kekMoved = true;
    }
    // Scored before the change, reported after it: the advisory must not be
    // able to influence whether the change happens, so it is captured here and
    // only reported once the outcome is already decided.
    const oldScore = scoreOldPassword(oldpwbox.value);

    await token.changePassword(oldpwbox.value, pw1.value);
    createAlert(
      "pw-change-success-title",
      pw1.value == "" ? "settings-pp-erased-ok" : "pp-change-ok"
    );
    // Item 59: an existing weak password is reported, not enforced. Nothing
    // here can undo the change or block it -- the password has already changed
    // and the dialog is about to close.
    if (oldScore?.belowPolicy) {
      console.warn(
        `Primary Password: the previous password was below the ` +
          `"${oldScore.tier}" policy (score ${oldScore.score})`
      );
    }
    window.close();
  } catch (e) {
    if (kekMoved) {
      await ProfileKekPassword.update(pw1.value, oldpwbox.value).catch(
        rollbackError =>
          console.error("Failed to roll back the lockstore KEK", rollbackError)
      );
    }
    let nssErrorsService = Cc["@mozilla.org/nss_errors_service;1"].getService(
      Ci.nsINSSErrorsService
    );
    // SEC_ERROR_BASE + 15 = SEC_ERROR_BAD_PASSWORD
    let badPasswordResult = nssErrorsService.getXPCOMFromNSSError(
      Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE + 15
    );
    // The lockstore unlock reports a wrong password as NS_ERROR_ABORT rather
    // than the token's bad-password code. Only reachable with kekMoved unset:
    // past that point the KEK is done with and the token, which reports
    // failures as NSS codes, is what failed.
    if (
      e.result == badPasswordResult ||
      (!kekMoved && e.result == Cr.NS_ERROR_ABORT)
    ) {
      oldpwbox.focus();
      oldpwbox.setAttribute("value", "");
      createAlert("pw-change-failed-title", "incorrect-pp");
    } else {
      createAlert("pw-change-failed-title", "failed-pp-change");
    }
  }
}

/**
 * The one evaluation of the typed password.
 *
 * Both the meter and the acceptance gate read this, and that is the point of
 * the function existing: when a policy is set, a password can no longer look
 * strong on the meter and be refused by the gate, or the reverse. They are two
 * renderings of one answer.
 *
 * Without a policy there is no gate to disagree with, so `meter` falls back to
 * the heuristic this dialog has always used and `failures` is empty. That is
 * deliberate: this file is shared with Firefox, and replacing its meter with
 * an estimator would be a behaviour change to the normal build made through a
 * fork's preference.
 *
 * @param {string} password
 * @returns {{meter: number, failures: string[], score: number|null}}
 *   `meter` is the 0-100 value for the progress bar; `failures` is empty when
 *   there is no policy, or when the password satisfies it; `score` is the
 *   estimator's 0-4, or null when no policy means it was never computed.
 */
function evaluatePassword(password) {
  if (!gPolicy) {
    return {
      meter: legacyMeter(password),
      failures: [],
      score: null,
      reasonL10n: null,
    };
  }

  // Computed once and reused: `failingRules()` accepts the score so the
  // estimator does not run twice per keystroke, and the meter reads the same
  // number the gate refused on. `reasonL10n` comes from the same call, so the
  // explanation cannot describe a different score from the one refused.
  const { score, reasonL10n } =
    PrimaryPasswordPolicy.estimateScore(password);
  const failures = password
    ? PrimaryPasswordPolicy.failingRules(password, gPolicy.rules, () => ({
        score,
      }))
    : [];

  // An empty password is the removal case: no bar, nothing refused.
  const meter = password ? meterForScore(score) : 0;
  return { meter, failures, score, reasonL10n };
}

/**
 * Maps the estimator's 0-4 onto the progress bar's 0-100.
 *
 * Four equal bands rather than a continuous scale from `guesses_log10`: the
 * score is what the policy compares against, so the bar showing anything else
 * would be a second opinion about the same password.
 *
 * @param {number|null} score
 * @returns {number}
 */
function meterForScore(score) {
  if (!Number.isInteger(score) || score < 0 || score > 4) {
    // The estimator could not be used. Show nothing rather than a guess, and
    // let the policy text carry the refusal -- a bar at 0 reads as "empty",
    // which is a different claim from "not measured".
    return 0;
  }
  return score * 25;
}

/**
 * The dialog's long-standing heuristic, kept for the no-policy case only.
 *
 * @param {string} pw
 * @returns {number} 0-100.
 */
function legacyMeter(pw) {
  var pwlength = pw.length > 5 ? 5 : pw.length;
  var numnumeric = pw.replace(/[0-9]/g, "");
  var numeric = pw.length - numnumeric.length;
  if (numeric > 3) {
    numeric = 3;
  }
  var symbols = pw.replace(/\W/g, "");
  var numsymbols = pw.length - symbols.length;
  if (numsymbols > 3) {
    numsymbols = 3;
  }
  var numupper = pw.replace(/[A-Z]/g, "");
  var upper = pw.length - numupper.length;
  if (upper > 3) {
    upper = 3;
  }
  var pwstrength =
    pwlength * 10 - 20 + numeric * 10 + numsymbols * 15 + upper * 10;
  if (pwstrength < 0) {
    pwstrength = 0;
  }
  if (pwstrength > 100) {
    pwstrength = 100;
  }
  return pwstrength;
}

function setPasswordStrength() {
  // One computation: the same evaluation the gate uses.
  const pw = document.getElementById("pw1").value;
  const { meter } = evaluatePassword(pw);
  document.getElementById("pwmeter").value = meter;
}

/**
 * Scores the existing password the user just typed, as advice.
 *
 * Returns null rather than throwing, and returns null whenever there is
 * nothing to say -- no policy, no plaintext, or an estimator that could not
 * answer. The caller reports and never acts on it: Item 59 requires that a
 * weak existing password cannot keep anyone out of their own profile.
 *
 * The deliberate position worth recording: this is the only place an existing
 * password's plaintext reaches JavaScript. The unlock prompt belongs to the
 * platform and the string passes from that dialog into NSS without crossing
 * script, so scoring at *unlock* would mean replacing the window watcher and
 * intercepting every dialog in the application. That trade is not worth a
 * notice, and the plan records it as the reason this item is Partial.
 *
 * In Firefox the `PrimaryPassword` getter is undefined, so this returns null
 * and the dialog behaves exactly as before.
 *
 * @param {string} password
 * @returns {{score: number, belowPolicy: boolean, tier: string}|null}
 */
function scoreOldPassword(password) {
  if (!password) {
    return null;
  }
  try {
    // The policy module holds the tiers and the estimator, so the question is
    // answered there rather than in this dialog -- and it stays inside the
    // one namespace a toolkit file may reach.
    const result = PrimaryPasswordPolicy.scoreExistingPassword(
      password,
      Services.prefs.getStringPref(PrimaryPasswordPolicy.TIER_PREF, ""),
      readCustomPolicy()
    );
    if (!result.scored) {
      return null;
    }
    return {
      score: result.score,
      belowPolicy: result.belowPolicy,
      tier: result.tier,
    };
  } catch (ex) {
    console.error("Primary Password: old password not scored", ex);
    return null;
  }
}

/**
 * Shows which policy rules the typed password fails, and why, and reports
 * whether any do. The element is left hidden when no policy is set, so no new
 * markup appears for an application that does not configure one.
 *
 * Each failing rule is named by its own localized message, and a strength
 * failure is followed by the pattern that explains it -- "this is a common
 * word" teaches, where "too weak" does not. The list comes from the rule data
 * rather than from a chain of conditions, so a rule added to
 * `PrimaryPasswordPolicy.RULES` appears here without a change.
 *
 * @param {string} password
 * @param {object} [evaluation] The result of `evaluatePassword()` for this
 *   password. Passed in so the meter and this text cannot disagree.
 * @returns {boolean} true when the password satisfies the policy, or when
 *   there is no policy.
 */
function updatePolicyFeedback(password, evaluation) {
  const el = document.getElementById("pw-policy");
  if (!gPolicy) {
    el.hidden = true;
    return true;
  }
  const { failures, reasonL10n } = evaluation ?? evaluatePassword(password);
  // An empty password is the removal case, which the dialog's own rules
  // govern; nothing is reported against it.
  if (!password || !failures.length) {
    el.hidden = true;
    return true;
  }

  const parts = failures.map(rule => textForRule(rule));
  if (failures.includes("strength") && reasonL10n) {
    parts.push(gPolicyText.get(reasonL10n) ?? reasonL10n);
  }

  el.hidden = false;
  el.textContent = parts.join(" ");
  return false;
}

/**
 * The localized wording for one failing rule.
 *
 * @param {string} rule A rule id from `PrimaryPasswordPolicy`.
 * @returns {string} The formatted message, or the rule id when the string is
 *   not available -- odd to read, but never a hang and never a blank.
 */
function textForRule(rule) {
  const id = PrimaryPasswordPolicy.ruleL10nId(rule);
  return (id && gPolicyText.get(id)) || rule;
}

function checkPasswords() {
  var pw1 = document.getElementById("pw1").value;
  var pw2 = document.getElementById("pw2").value;
  var ok = document.getElementById("changemp").getButton("accept");

  let token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
  if (!token.hasPassword && pw1 == "") {
    // The default password for the internal key token is the empty string. It
    // makes no sense to change the password from the empty string to the empty
    // string.
    ok.toggleAttribute("disabled", true);
    return;
  }

  // A policy tier is enforced here, and only when one is configured. It can
  // disable the accept button but never enables it: the existing rules above
  // still decide whether this is a change the dialog may perform at all.
  //
  // The evaluation is made once and passed to the feedback renderer, so the
  // text under the field and the button's state come from the same answer.
  const evaluation = evaluatePassword(pw1);
  const policyOk = updatePolicyFeedback(pw1, evaluation);

  let enabled =
    pw1 == pw2 &&
    (pw1 != "" || Services.policies.isAllowed("removeMasterPassword")) &&
    policyOk;
  ok.toggleAttribute("disabled", !enabled);
}

window.addEventListener("load", init);
