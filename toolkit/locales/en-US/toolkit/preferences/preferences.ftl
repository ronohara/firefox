# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set-password-not-set =
    .label = Current password:
    .placeholder = (not set)

failed-pp-change = Unable to change Primary Password.
incorrect-pp = You did not enter the correct current Primary Password. Please try again.
pp-change-ok = Primary Password successfully changed.

settings-pp-erased-ok = You have deleted your Primary Password. Stored passwords and certificate private keys managed by { -brand-short-name } will not be protected.

pp-change2empty-in-fips-mode = You are currently in FIPS mode. FIPS requires a non-empty Primary Password.
pw-change-success-title = Password Change Succeeded
pw-change-failed-title = Password Change Failed
pw-remove-button =
    .label = Remove

primary-password-dialog =
    .title = Primary Password
set-password-old =
    .label = Current password:
set-password-new =
    .label = Enter new password:
set-password-reenter =
    .label = Re-enter password:
set-password-meter = Password quality meter
set-password-meter-loading = Loading
primary-password-required-by-policy = Your organization requires that you have a Primary Password set in order to save logins and passwords.
primary-password-description = A Primary Password is used to protect some sensitive information, like logins and passwords, on this device. If you create a Primary Password you will be asked to enter it once per session when { -brand-short-name } retrieves saved information protected by the password.
primary-password-warning = Please make sure you remember the Primary Password you have set. If you forget your Primary Password, you will be unable to access any of the information protected by it on this device.

remove-primary-password =
    .title = Remove Primary Password
remove-primary-password-info =
    .value = You must enter your current password to proceed.
remove-primary-password-warning1 = Your Primary Password is used to protect sensitive information like logins and passwords.
remove-primary-password-warning2 = If you remove your Primary Password your information will not be protected if your computer is compromised.
remove-password-old =
    .label = Current password:

## Password policy
##
## Shown under the new-password field when a policy tier is configured and the
## typed password fails it. Each rule is its own message so the user is told
## what to change rather than only that something is wrong.

#   $min (Number) - the minimum number of characters the policy requires
primary-password-policy-min-length = At least { $min } characters

primary-password-policy-uppercase = An uppercase letter

primary-password-policy-lowercase = A lowercase letter

primary-password-policy-digit = A digit

primary-password-policy-special = A symbol

# Shown when the strength estimator scores the password below the tier's
# minimum. Deliberately vague about why: the reason follows in one of the
# primary-password-policy-reason-* messages.
primary-password-policy-strength = A less predictable password

## Why the estimator scored the password low.
##
## Mapped from zxcvbn's `pattern` field for each matched sequence, which is a
## closed set of seven values, rather than from its English `warning` strings --
## those are prose inside a vendored library and change without notice.

primary-password-policy-reason-dictionary = It contains a common word or password.

primary-password-policy-reason-spatial = It is a pattern of nearby keys on the keyboard.

primary-password-policy-reason-repeat = It repeats the same characters or words.

primary-password-policy-reason-sequence = It is a run of characters in order, like abc or 6543.

primary-password-policy-reason-date = It looks like a date or a year.

primary-password-policy-reason-bruteforce = It is short.
