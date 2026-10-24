/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  PrimaryPasswordPolicy: "resource://gre/modules/PrimaryPasswordPolicy.sys.mjs",
  ProfileKekPassword: "resource://gre/modules/ProfileKekPassword.sys.mjs",
});

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
 * Reads the tier preference and resolves it.
 *
 * @returns {{name: string, rules: object}|null} null when no policy is set.
 */
function readPolicy() {
  const tier = Services.prefs.getStringPref(
    lazy.PrimaryPasswordPolicy.TIER_PREF,
    ""
  );
  if (!tier) {
    return null;
  }
  let custom = null;
  const raw = Services.prefs.getStringPref(
    lazy.PrimaryPasswordPolicy.CUSTOM_PREF,
    ""
  );
  if (raw) {
    try {
      custom = JSON.parse(raw);
    } catch (ex) {
      console.error("Primary Password policy: custom tier is not JSON", ex);
    }
  }
  const resolved = lazy.PrimaryPasswordPolicy.resolveTier(tier, custom);
  if (resolved.unknownTier) {
    console.warn(
      `Primary Password policy: unknown tier "${resolved.requested}", ` +
        `falling back to "${resolved.name}"`
    );
  }
  return { name: resolved.name, rules: resolved.rules };
}

function init() {
  gPolicy = readPolicy();
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
    if (!token.hasPassword || (await lazy.ProfileKekPassword.exists())) {
      await lazy.ProfileKekPassword.update(oldpwbox.value, pw1.value);
      kekMoved = true;
    }
    await token.changePassword(oldpwbox.value, pw1.value);
    createAlert(
      "pw-change-success-title",
      pw1.value == "" ? "settings-pp-erased-ok" : "pp-change-ok"
    );
    window.close();
  } catch (e) {
    if (kekMoved) {
      await lazy.ProfileKekPassword.update(pw1.value, oldpwbox.value).catch(
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
    return { meter: legacyMeter(password), failures: [], score: null };
  }

  // Computed once and reused: `failingRules()` accepts the score so the
  // estimator does not run twice per keystroke, and the meter reads the same
  // number the gate refused on.
  const { score } = lazy.PrimaryPasswordPolicy.estimateScore(password);
  const failures = password
    ? lazy.PrimaryPasswordPolicy.failingRules(password, gPolicy.rules, () => ({
        score,
      }))
    : [];

  // An empty password is the removal case: no bar, nothing refused.
  const meter = password ? meterForScore(score) : 0;
  return { meter, failures, score };
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
 * Shows which policy rules the typed password fails, and reports whether any
 * do. The element is left hidden when no policy is set, so no new markup
 * appears for an application that does not configure one.
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
  // Takes the evaluation the meter also read, rather than recomputing: with an
  // estimator behind it, computing twice per keystroke would be wasteful and
  // -- worse -- two computations could disagree, which is the failure this
  // item exists to remove.
  const { failures } = evaluation ?? evaluatePassword(password);
  // An empty password is the removal case, which the dialog's own rules
  // govern; nothing is reported against it.
  if (!password || !failures.length) {
    el.hidden = true;
    return true;
  }
  el.hidden = false;
  el.textContent = `${gPolicy.name} policy: ${failures
    .map(describeRule)
    .join("; ")}`;
  return false;
}

/**
 * Human wording for a failing rule.
 *
 * Deliberately not localized in this change: the policy is new, the wording
 * is provisional, and adding Fluent strings for a feature whose tier is still
 * being chosen would fix the text before the requirement is settled. The plan
 * records this as a follow-up rather than presenting the English as final.
 *
 * @param {string} rule
 * @returns {string}
 */
function describeRule(rule) {
  switch (rule) {
    case "min-length":
      return `at least ${gPolicy.rules.minLength} characters`;
    case "uppercase":
      return "an uppercase letter";
    case "lowercase":
      return "a lowercase letter";
    case "digit":
      return "a digit";
    case "special":
      return "a symbol";
    case "strength":
      return "a less predictable password";
    default:
      return rule;
  }
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
