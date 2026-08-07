<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\audit;

use InvalidArgumentException;

/**
 * AuthEvent is the neutral, immutable value object an emitter (Warden, Warp)
 * hands the Auth Kit `audit` service to describe one authentication-related
 * fact — a passwordless login, a passkey enrollment, an IdP-initiated session
 * revocation, a SCIM (de)provisioning. A sink (e.g. Password Policy's audit-log
 * adapter) receives it and decides what to persist.
 *
 * Like [[\craftpulse\authkit\passwords\PasswordValidationResult]] this is a plain
 * final value class rather than a `craft\base\Model` subclass, and its shape is
 * frozen at 1.2.0: the six readonly properties and the constructor signature are
 * the contract. Treat any change to that shape as a major version bump. New
 * event-name constants, by contrast, are additive — they ship in minors, and
 * sinks that don't recognize a name ignore it silently (forward compatibility:
 * an emitter on a newer Auth Kit may send names an older sink has never heard
 * of).
 *
 * Contract rules the value object enforces and emitters must honor:
 *
 * - [[$outcome]] must be one of [[OUTCOME_SUCCESS]] or [[OUTCOME_FAILURE]];
 *   anything else is a programming error and throws.
 * - [[$details]] must be scalar-only and carry no PII — no emails, raw IPs, or
 *   raw user agents. Only `bool`, `int`, `float`, and `string` values are
 *   accepted; a non-scalar value throws. A downstream sink's allowlist may
 *   strip unknown keys, but future sinks won't, so the neutral contract keeps
 *   the payload clean at the source.
 * - [[$name]] is deliberately *not* validated against the known constants:
 *   forward compatibility requires that a newer emitter's name survive an older
 *   Auth Kit, and sinks tolerate unknown names by design.
 *
 * @author CraftPulse
 * @since 1.2.0
 */
final class AuthEvent
{
    // Const Properties
    // =========================================================================

    /**
     * @var string A magic-link login succeeded (`login.magic_link`).
     *
     * @since 1.2.0
     */
    public const LOGIN_MAGIC_LINK = 'login.magic_link';

    /**
     * @var string A login arrived from a coarse location (country and city) the
     * user had never successfully signed in from before (`login.new_location`);
     * `details` carries `country`, and `city` when one was resolved.
     *
     * The location itself, not the sign-in, is the audit fact: the login it
     * accompanies is reported separately by whichever `LOGIN_*` constant names
     * the channel it arrived on. Emitted once per user and place across the
     * whole install, however many consumers are watching, so it never doubles
     * up.
     *
     * A country is always present — a login whose IP could not be placed is
     * never flagged — while `city` is absent for a country-only resolution.
     *
     * @since 1.10.0
     */
    public const LOGIN_NEW_LOCATION = 'login.new_location';

    /**
     * @var string A one-time-passcode login succeeded (`login.otp`).
     *
     * @since 1.2.0
     */
    public const LOGIN_OTP = 'login.otp';

    /**
     * @var string A passkey (WebAuthn) login succeeded (`login.passkey`).
     *
     * @since 1.2.0
     */
    public const LOGIN_PASSKEY = 'login.passkey';

    /**
     * @var string A single-sign-on login succeeded (`login.sso`); `details`
     * carries the identity provider handle under `provider`.
     *
     * @since 1.2.0
     */
    public const LOGIN_SSO = 'login.sso';

    /**
     * @var string Emitted by Password Policy's outcome column: the event failed.
     *
     * @since 1.2.0
     */
    public const OUTCOME_FAILURE = 'failure';

    /**
     * @var string Matches Password Policy's outcome column: the event succeeded.
     *
     * @since 1.2.0
     */
    public const OUTCOME_SUCCESS = 'success';

    /**
     * @var string A passkey was deleted (`passkey.deleted`).
     *
     * @since 1.2.0
     */
    public const PASSKEY_DELETED = 'passkey.deleted';

    /**
     * @var string A passkey was enrolled (`passkey.enrolled`).
     *
     * @since 1.2.0
     */
    public const PASSKEY_ENROLLED = 'passkey.enrolled';

    /**
     * @var string A passwordless registration was fulfilled
     * (`registration.fulfilled`).
     *
     * @since 1.2.0
     */
    public const REGISTRATION_FULFILLED = 'registration.fulfilled';

    /**
     * @var string A user was deprovisioned (`scim.deprovisioned`); `details`
     * carries the `trigger` (`scim` | `jit`).
     *
     * @since 1.2.0
     */
    public const SCIM_DEPROVISIONED = 'scim.deprovisioned';

    /**
     * @var string A user was provisioned (`scim.provisioned`); `details` carries
     * the `trigger` (`scim` | `jit`).
     *
     * @since 1.2.0
     */
    public const SCIM_PROVISIONED = 'scim.provisioned';

    /**
     * @var string A session was revoked (`session.revoked`); `details` carries
     * the `scope` (`single` | `others` | `backchannel` | `frontchannel` |
     * `global`). `single` and `others` are user-initiated device revocations;
     * `backchannel` and `frontchannel` are IdP-initiated logout channels;
     * `global` is a Global Token Revocation request. Scope values are additive
     * vocabulary — sinks ignore values they don't recognize.
     *
     * With `OUTCOME_FAILURE`, the event records an attempted revocation that
     * was refused before any session was touched — e.g. a back-channel
     * logout_token that failed signature validation. No session died; the
     * attempt itself is the audit fact.
     *
     * @since 1.2.0
     */
    public const SESSION_REVOKED = 'session.revoked';

    /**
     * @var string A user was deprovisioned (`user.deprovisioned`); `details`
     * carries the `trigger`, the channel the deprovision arrived on (`scim` |
     * `webhook` | `sync`). Trigger values are additive vocabulary — sinks
     * ignore values they don't recognize.
     *
     * Channel-neutral, unlike [[SCIM_DEPROVISIONED]]: an emitter deprovisions
     * from a directory webhook or a scheduled reconciliation sweep as well as
     * from a SCIM push, and naming every one of those `scim.*` misfiles the
     * fact. Prefer this constant for new emitters.
     *
     * @since 1.9.0
     */
    public const USER_DEPROVISIONED = 'user.deprovisioned';

    /**
     * @var string A user was provisioned (`user.provisioned`); `details`
     * carries the `trigger`, the channel the provision arrived on (`jit` |
     * `scim`). Trigger values are additive vocabulary — sinks ignore values
     * they don't recognize.
     *
     * Channel-neutral, unlike [[SCIM_PROVISIONED]]: a just-in-time provision
     * at first login is not a SCIM fact. Prefer this constant for new
     * emitters.
     *
     * @since 1.9.0
     */
    public const USER_PROVISIONED = 'user.provisioned';

    /**
     * @var string A deprovisioned user was restored (`user.restored`) —
     * unsuspended, reactivated, or both; `details` carries the `trigger`, the
     * channel the restore arrived on (`scim` | `webhook`). Trigger values are
     * additive vocabulary — sinks ignore values they don't recognize.
     *
     * The counterpart to [[USER_DEPROVISIONED]]: an account regaining access
     * is as much an audit fact as one losing it.
     *
     * @since 1.9.0
     */
    public const USER_RESTORED = 'user.restored';

    // Public Properties
    // =========================================================================

    /**
     * @var int|null The acting admin or system user, or null when the subject
     * acted on their own behalf (self-service) or no actor applies (system).
     *
     * @since 1.2.0
     */
    public readonly ?int $actorId;

    /**
     * @var array<string, scalar> Scalar-only, non-PII context for the event
     * (e.g. `['provider' => 'okta']`, `['scope' => 'backchannel']`).
     *
     * @since 1.2.0
     */
    public readonly array $details;

    /**
     * @var string The emitting plugin's handle (e.g. `warden`, `warp`).
     *
     * @since 1.2.0
     */
    public readonly string $emitter;

    /**
     * @var string The neutral event name — one of the `LOGIN_*`, `PASSKEY_*`,
     * `REGISTRATION_*`, `SCIM_*`, `SESSION_*`, or `USER_*` constants. Not
     * validated: sinks tolerate unknown names for forward compatibility.
     *
     * @since 1.2.0
     */
    public readonly string $name;

    /**
     * @var string The outcome — [[OUTCOME_SUCCESS]] or [[OUTCOME_FAILURE]].
     *
     * @since 1.2.0
     */
    public readonly string $outcome;

    /**
     * @var int|null The subject user's id, or null when no user is resolved.
     *
     * @since 1.2.0
     */
    public readonly ?int $userId;

    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param string $name the neutral event name — one of the class constants,
     * though any string is accepted for forward compatibility
     * @param string $emitter the emitting plugin's handle (e.g. `warden`, `warp`)
     * @param string $outcome [[OUTCOME_SUCCESS]] or [[OUTCOME_FAILURE]]
     * @param int|null $userId the subject user's id, when resolved
     * @param array<string, scalar> $details scalar-only, non-PII context
     * @param int|null $actorId the acting admin or system user, null for self
     * @throws InvalidArgumentException if $outcome is not a known outcome
     * constant, or if any $details value is not scalar
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    public function __construct(
        string $name,
        string $emitter,
        string $outcome = self::OUTCOME_SUCCESS,
        ?int $userId = null,
        array $details = [],
        ?int $actorId = null,
    ) {
        if ($outcome !== self::OUTCOME_SUCCESS && $outcome !== self::OUTCOME_FAILURE) {
            throw new InvalidArgumentException(sprintf(
                'AuthEvent outcome must be "%s" or "%s", "%s" given.',
                self::OUTCOME_SUCCESS,
                self::OUTCOME_FAILURE,
                $outcome,
            ));
        }

        foreach ($details as $key => $value) {
            if (!is_scalar($value)) {
                throw new InvalidArgumentException(sprintf(
                    'AuthEvent details must be scalar-only; the "%s" value is %s.',
                    $key,
                    get_debug_type($value),
                ));
            }
        }

        $this->name = $name;
        $this->emitter = $emitter;
        $this->outcome = $outcome;
        $this->userId = $userId;
        $this->details = $details;
        $this->actorId = $actorId;
    }
}
