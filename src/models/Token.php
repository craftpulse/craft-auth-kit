<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\models;

use craft\base\Model;
use craft\helpers\DateTimeHelper;
use craft\helpers\Json;
use craftpulse\authkit\records\Token as TokenRecord;
use DateTime;

/**
 * Token models an issued passwordless credential — a magic link, an email OTP
 * code, or a registration link. The raw token is never persisted; only its
 * sha256 hash, single-use flag, expiry, and (for OTP) the attempt counters live
 * here, mirroring core's hashed password-reset code pattern.
 *
 * A registration token carries a null `userId` (no account exists yet) and the
 * target email in its `payload`; every other type is tied to a user.
 *
 * Usability is decided by [[isUsable()]]: a token is good only while it is
 * neither expired, already consumed, nor out of attempts.
 *
 * @author CraftPulse
 * @since 1.0.0
 */
class Token extends Model
{
    // Const Properties
    // =========================================================================

    /**
     * @var string The magic-link token type — an unguessable secret, no attempt cap.
     *
     * @since 1.0.0
     */
    public const TYPE_MAGIC_LINK = 'magic-link';

    /**
     * @var string The email-bound guest OTP token type — a short numeric code,
     * attempt-capped, bound to an arbitrary email rather than a user. Carries a
     * null `userId` and the sha256 of the lowercased email in `subject`. Proves
     * control of the mailbox; the holder never becomes a user or a session.
     *
     * @since 1.6.0
     */
    public const TYPE_GUEST_OTP = 'guest-otp';

    /**
     * @var string The email OTP token type — a short numeric code, attempt-capped.
     *
     * @since 1.0.0
     */
    public const TYPE_OTP = 'otp';

    /**
     * @var string The registration token type — an unguessable secret proving
     * mailbox possession for an address that has no user yet. Carries a null
     * `userId` and the target email in its payload.
     *
     * @since 1.2.0
     */
    public const TYPE_REGISTER = 'register';

    // Public Properties
    // =========================================================================

    /**
     * @var int The number of failed consume attempts recorded against the token.
     *
     * @since 1.0.0
     */
    public int $attempts = 0;

    /**
     * @var DateTime|null The date the token was consumed, or null if unused.
     *
     * @since 1.0.0
     */
    public ?DateTime $dateConsumed = null;

    /**
     * @var DateTime|null The date the token row was created.
     *
     * @since 1.0.0
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var DateTime|null The date the token row was last updated.
     *
     * @since 1.0.0
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var DateTime|null The date after which the token can no longer be consumed.
     *
     * @since 1.0.0
     */
    public ?DateTime $expiryDate = null;

    /**
     * @var int|null The token's ID.
     *
     * @since 1.0.0
     */
    public ?int $id = null;

    /**
     * @var int|null The maximum number of failed consume attempts, or null for
     * no cap (magic links, whose secret is unguessable).
     *
     * @since 1.0.0
     */
    public ?int $maxAttempts = null;

    /**
     * @var array<string, mixed>|null Arbitrary issuance metadata (e.g. a returnUrl).
     *
     * @since 1.0.0
     */
    public ?array $payload = null;

    /**
     * @var string|null The issuing consumer's label (e.g. a plugin handle).
     * Tokens are consumed strictly within their origin; null = legacy scope.
     *
     * @since 1.4.0
     */
    public ?string $origin = null;

    /**
     * @var string|null The lookup key for an email-bound guest OTP — the sha256
     * of the lowercased email, never the raw address. Null for user-bound and
     * legacy tokens, which are looked up by `userId`.
     *
     * @since 1.6.0
     */
    public ?string $subject = null;

    /**
     * @var string|null The sha256 hash of the raw token. Never the raw token itself.
     *
     * @since 1.0.0
     */
    public ?string $tokenHash = null;

    /**
     * @var string|null The token type — [[TYPE_MAGIC_LINK]] or [[TYPE_OTP]].
     *
     * @since 1.0.0
     */
    public ?string $type = null;

    /**
     * @var string|null The token's UID.
     *
     * @since 1.0.0
     */
    public ?string $uid = null;

    /**
     * @var int|null The ID of the Craft user the token authenticates.
     *
     * @since 1.0.0
     */
    public ?int $userId = null;

    // Public Methods
    // =========================================================================

    /**
     * Creates a Token model from its record, converting raw SQL datetime
     * strings and the JSON payload at the hydration boundary.
     *
     * @param TokenRecord $record the record to hydrate from
     * @return self
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public static function fromRecord(TokenRecord $record): self
    {
        $payload = $record->payload;

        if (is_string($payload) && $payload !== '') {
            $decoded = Json::decodeIfJson($payload);
            $payload = is_array($decoded) ? $decoded : null;
        } elseif (!is_array($payload)) {
            $payload = null;
        }

        $model = new self();
        $model->id = (int)$record->id;
        $model->userId = $record->userId !== null ? (int)$record->userId : null;
        $model->type = $record->type;
        $model->origin = $record->origin ?? null;
        $model->subject = $record->subject ?? null;
        $model->tokenHash = $record->tokenHash;
        $model->expiryDate = DateTimeHelper::toDateTime($record->expiryDate) ?: null;
        $model->dateConsumed = DateTimeHelper::toDateTime($record->dateConsumed) ?: null;
        $model->attempts = (int)$record->attempts;
        $model->maxAttempts = $record->maxAttempts !== null ? (int)$record->maxAttempts : null;
        $model->payload = $payload;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = $record->uid;

        return $model;
    }

    /**
     * Returns whether the token has already been consumed.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function isConsumed(): bool
    {
        return $this->dateConsumed !== null;
    }

    /**
     * Returns whether the token's expiry has passed.
     *
     * A token with no expiry is treated as expired — fail closed; every issued
     * token is given one.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function isExpired(): bool
    {
        if ($this->expiryDate === null) {
            return true;
        }

        return $this->expiryDate < DateTimeHelper::now();
    }

    /**
     * Returns whether the token has exhausted its allowed failed attempts. A
     * null [[maxAttempts]] (magic links) is never out of attempts.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function isOutOfAttempts(): bool
    {
        if ($this->maxAttempts === null) {
            return false;
        }

        return $this->attempts >= $this->maxAttempts;
    }

    /**
     * Returns whether the token may still be consumed — neither expired,
     * already used, nor out of attempts.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function isUsable(): bool
    {
        return !$this->isExpired() && !$this->isConsumed() && !$this->isOutOfAttempts();
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     * @return array<int, mixed>
     */
    protected function defineRules(): array
    {
        $rules = parent::defineRules();
        $rules[] = [['type', 'tokenHash', 'expiryDate'], 'required'];
        // A user-less token — a registration link (email in the payload) or an
        // email-bound guest OTP (email hashed into `subject`) — carries no
        // userId; every other type requires one.
        $rules[] = [
            ['userId'],
            'required',
            'when' => static fn(self $model): bool => !in_array($model->type, [self::TYPE_REGISTER, self::TYPE_GUEST_OTP], true),
        ];
        // A guest OTP is looked up by its subject, so it must carry one.
        $rules[] = [
            ['subject'],
            'required',
            'when' => static fn(self $model): bool => $model->type === self::TYPE_GUEST_OTP,
        ];
        $rules[] = [['userId', 'attempts', 'maxAttempts'], 'integer'];
        $rules[] = [['type'], 'in', 'range' => [self::TYPE_MAGIC_LINK, self::TYPE_OTP, self::TYPE_GUEST_OTP, self::TYPE_REGISTER]];
        $rules[] = [['origin'], 'string', 'max' => 32];
        $rules[] = [['subject', 'tokenHash'], 'string', 'length' => 64];

        return $rules;
    }
}
