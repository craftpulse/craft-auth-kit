<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
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
 * @author Michael Thomas
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
     * the `scope` (`single` | `others` | `backchannel`).
     *
     * @since 1.2.0
     */
    public const SESSION_REVOKED = 'session.revoked';

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
     * `REGISTRATION_*`, `SCIM_*`, or `SESSION_*` constants. Not validated: sinks
     * tolerate unknown names for forward compatibility.
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
     * @author Michael Thomas
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
