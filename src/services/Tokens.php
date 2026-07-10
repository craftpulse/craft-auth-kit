<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\services;

use Carbon\Carbon;
use Craft;
use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\Json;
use craft\helpers\UrlHelper;
use craft\mail\Mailer;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\models\Token;
use craftpulse\authkit\records\Token as TokenRecord;
use Throwable;
use yii\base\Component;
use yii\caching\CacheInterface;
use yii\db\Expression;

/**
 * Tokens issues and consumes passwordless email credentials — both magic links
 * and one-time codes (OTP) — backed by a single hashed, single-use, TTL'd
 * token store.
 *
 * Security invariants (SLOW MODE — see CLAUDE.md):
 *
 * - The raw token (32 random bytes for a magic link, a short numeric code for
 *   an OTP) is never persisted; only its sha256 hash is stored, and the hash
 *   is what every lookup compares against. The raw value lives only in the
 *   emailed link or code. An OTP hash is additionally scoped to its user's
 *   UID — the code pool is tiny and deterministic, so two users holding the
 *   same code would otherwise collide on the unique `tokenHash` index.
 * - Tokens are single-use: consumption burns the token with a conditional
 *   `UPDATE ... WHERE dateConsumed IS NULL`, so a double-submit or a parallel
 *   request can never log in twice off one token.
 * - Issuance is enumeration-safe: an unknown or ineligible address takes the
 *   same code path (a constant-time equalizer plus a per-address throttle) and
 *   never reveals whether an account exists. The caller surfaces an identical
 *   response either way.
 * - A token is only honoured while its target user is still active — a
 *   suspended or deactivated account cannot log back in off a stale token.
 *
 * Magic links carry an unguessable 32-byte secret, so they have no attempt
 * cap. OTP codes are short and brute-forceable, so they are scoped to the
 * user: a wrong code increments the attempt counter, and once `maxAttempts`
 * failures accrue the code is burned and further attempts fail closed.
 * Issuing a new OTP supersedes any prior unconsumed OTP for the same user.
 *
 * Per-IP rate limiting is applied at the controller (core's `RateLimiter`
 * filter); the per-address throttle here protects every channel, including
 * programmatic issuance.
 *
 * An instance of the service is available via `AuthKit::$plugin->getTokens()`.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class Tokens extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var int The default token lifetime, in seconds (15 minutes).
     *
     * @since 1.0.0
     */
    public const DEFAULT_TTL = 900;

    /**
     * @var string A fixed bcrypt hash for the timing equalizer — never a real
     * credential. Mirrors core's `_hashCheck()` pattern.
     *
     * @since 1.0.0
     */
    public const DUMMY_HASH = '$2y$13$nj9aiBeb7RfEfYP3Cum6Revyu14QelGGxwcnFUKXIrQUitSodEPRi';

    /**
     * @var string The system message key used to compose the magic-link email.
     *
     * @since 1.0.0
     */
    public const MESSAGE_KEY_MAGIC_LINK = 'auth_kit_magic_link';

    /**
     * @var string The system message key used to compose the OTP email.
     *
     * @since 1.0.0
     */
    public const MESSAGE_KEY_OTP = 'auth_kit_otp';

    /**
     * @var int The number of random bytes in a raw magic-link token before hex
     * encoding.
     *
     * @since 1.0.0
     */
    public const TOKEN_BYTES = 32;

    /**
     * @var string The query param carrying the raw token on the magic-link
     * verify URL. Deliberately NOT `token`: Craft's web application reserves
     * its `tokenParam` (default `token`) for routed tokens and responds 400
     * to any request naming it with a value Craft did not issue — a magic
     * link using it can never reach the consuming controller.
     *
     * @since 1.0.0
     */
    public const TOKEN_PARAM = 'mlToken';

    /**
     * @event TokenEvent The event that is triggered after a token is issued.
     * @since 1.0.0
     */
    public const EVENT_AFTER_ISSUE_TOKEN = 'afterIssueToken';

    /**
     * @event TokenEvent The event that is triggered before a token is consumed,
     * while it is still usable. Canceling the event refuses the login and
     * leaves the token unburned.
     * @since 1.0.0
     */
    public const EVENT_BEFORE_CONSUME_TOKEN = 'beforeConsumeToken';

    /**
     * @event TokenEvent The event that is triggered after a token is consumed
     * and the user resolved.
     * @since 1.0.0
     */
    public const EVENT_AFTER_CONSUME_TOKEN = 'afterConsumeToken';

    // Public Properties
    // =========================================================================

    /**
     * @var Mailer|null The mailer used to deliver links and codes. Defaults to
     * Craft's configured mailer; injectable for tests.
     *
     * @since 1.0.0
     */
    public ?Mailer $mailer = null;

    /**
     * @var string The site route the magic-link verify URL is built against.
     * Auth Kit imposes no routes — the consuming plugin registers this URL and
     * may override the route here. The raw token is appended as a
     * [[TOKEN_PARAM]] query parameter.
     *
     * @since 1.0.0
     */
    public string $magicLinkRoute = 'auth-kit/magic-link/verify';

    /**
     * @var int The default maximum number of failed OTP consume attempts before
     * the code is burned.
     *
     * @since 1.0.0
     */
    public int $otpMaxAttempts = 5;

    /**
     * @var int The number of digits in an issued OTP code.
     *
     * @since 1.0.0
     */
    public int $otpDigits = 6;

    /**
     * @var int The maximum number of tokens that may be issued to a single
     * address within [[perEmailWindow]] seconds.
     *
     * @since 1.0.0
     */
    public int $perEmailLimit = 5;

    /**
     * @var int The per-address throttle window, in seconds.
     *
     * @since 1.0.0
     */
    public int $perEmailWindow = 300;

    /**
     * @var int The issued token lifetime, in seconds.
     *
     * @since 1.0.0
     */
    public int $tokenTtl = self::DEFAULT_TTL;

    // Public Methods
    // =========================================================================

    /**
     * Consumes a raw magic-link token and returns the user it logs in, or null
     * if the token is unknown, expired, already used, canceled by a handler,
     * or belongs to an account that is no longer active.
     *
     * @param string $rawToken the raw token from the login URL
     * @return User|null the user to log in, or null on any failure
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function consumeMagicLink(string $rawToken): ?User
    {
        $rawToken = trim($rawToken);

        if ($rawToken === '') {
            return null;
        }

        $record = TokenRecord::findOne([
            'type' => Token::TYPE_MAGIC_LINK,
            'tokenHash' => hash('sha256', $rawToken),
        ]);

        if ($record === null) {
            return null;
        }

        return $this->_finalizeConsume(Token::fromRecord($record));
    }

    /**
     * Consumes an OTP code for an email address and returns the user it logs
     * in, or null on any failure.
     *
     * The OTP is scoped to the user (the code is short and guessable): the
     * active code for the address's user is looked up, the submitted code is
     * compared in constant time, and on mismatch the attempt counter is
     * incremented — once [[maxAttempts]] failures accrue the code is burned.
     *
     * @param string $email the address the code was issued to
     * @param string $code the submitted OTP code
     * @return User|null the user to log in, or null on any failure
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function consumeOtp(string $email, string $code): ?User
    {
        $email = trim($email);
        $code = trim($code);

        if ($email === '' || $code === '') {
            $this->_equalizeTiming();

            return null;
        }

        $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($email);

        if ($user === null) {
            $this->_equalizeTiming();

            return null;
        }

        $record = TokenRecord::find()
            ->where(['type' => Token::TYPE_OTP, 'userId' => (int)$user->id, 'dateConsumed' => null])
            ->orderBy(['id' => SORT_DESC])
            ->one();

        if (!$record instanceof TokenRecord) {
            $this->_equalizeTiming();

            return null;
        }

        $model = Token::fromRecord($record);

        if (!$model->isUsable()) {
            // Equalize this branch too: a fast return here would distinguish
            // "this address has a stale OTP" from "unknown address" (which
            // pays the bcrypt cost above) — an account-existence oracle.
            $this->_equalizeTiming();

            return null;
        }

        // Constant-time comparison of the submitted code's hash against the
        // stored hash, so a wrong code is indistinguishable by timing.
        if (!hash_equals((string)$model->tokenHash, $this->_hashOtpCode($user, $code))) {
            $this->_registerFailedOtpAttempt($model);

            // Equalize this branch too: the failed-attempt bookkeeping is a
            // couple of indexed single-row UPDATEs (single-digit ms), while
            // every other failure branch pays one bcrypt verification — a
            // fast return here would distinguish "a live OTP exists for this
            // address" from "unknown address", an account-existence oracle.
            $this->_equalizeTiming();

            return null;
        }

        return $this->_finalizeConsume($model);
    }

    /**
     * Issues a magic link for an email address and emails it, when the address
     * belongs to an active user.
     *
     * Returns whether a link was actually issued — but callers facing the
     * public must respond identically regardless, to stay enumeration-safe.
     *
     * @param string $email the address to send a login link to
     * @param string|null $returnUrl the validated URL to return to after login
     * @return bool whether a link was issued
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function issueMagicLink(string $email, ?string $returnUrl = null): bool
    {
        $user = $this->_resolveIssuableUser($email);

        if ($user === null) {
            return false;
        }

        $rawToken = bin2hex(random_bytes(self::TOKEN_BYTES));
        $payload = ($returnUrl !== null && $returnUrl !== '') ? ['returnUrl' => $returnUrl] : null;

        $token = $this->_buildToken($user, Token::TYPE_MAGIC_LINK, $rawToken, null, $payload);

        if (!$this->_saveToken($token)) {
            return false;
        }

        $params = [self::TOKEN_PARAM => $rawToken];

        if ($returnUrl !== null && $returnUrl !== '') {
            $params['returnUrl'] = $returnUrl;
        }

        $url = UrlHelper::siteUrl($this->magicLinkRoute, $params);
        $this->_sendEmail(self::MESSAGE_KEY_MAGIC_LINK, $user, ['link' => $url, 'user' => $user]);

        $this->trigger(self::EVENT_AFTER_ISSUE_TOKEN, new TokenEvent(['token' => $token, 'user' => $user]));

        return true;
    }

    /**
     * Issues an OTP code for an email address and emails it, when the address
     * belongs to an active user. Issuing a new code supersedes (expires) any
     * prior unconsumed OTP for the same user.
     *
     * Returns whether a code was actually issued — but callers facing the
     * public must respond identically regardless, to stay enumeration-safe.
     *
     * @param string $email the address to send a code to
     * @return bool whether a code was issued
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function issueOtp(string $email): bool
    {
        $user = $this->_resolveIssuableUser($email);

        if ($user === null) {
            return false;
        }

        // Supersede any prior unconsumed OTP for this user so only the newest
        // code is live — an attacker cannot keep an old code's attempt budget.
        $this->_supersedeOtps((int)$user->id);

        $code = $this->_generateOtpCode();
        $token = $this->_buildToken($user, Token::TYPE_OTP, $code, $this->otpMaxAttempts, null);

        if (!$this->_saveToken($token)) {
            return false;
        }

        $this->_sendEmail(self::MESSAGE_KEY_OTP, $user, ['code' => $code, 'user' => $user]);

        $this->trigger(self::EVENT_AFTER_ISSUE_TOKEN, new TokenEvent(['token' => $token, 'user' => $user]));

        return true;
    }

    /**
     * Deletes every expired token. Safe to run on a schedule; consumed tokens
     * are pruned once their expiry passes.
     *
     * @return int the number of rows deleted
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function purgeExpiredTokens(): int
    {
        return Db::delete(Table::TOKENS, ['<', 'expiryDate', Db::prepareDateForDb(Carbon::now())]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds an unsaved token model for a user.
     *
     * @param User $user the target user
     * @param string $type the token type
     * @param string $rawToken the raw token whose hash is stored
     * @param int|null $maxAttempts the failed-attempt cap, or null for none
     * @param array<string, mixed>|null $payload arbitrary issuance metadata
     * @return Token
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _buildToken(User $user, string $type, string $rawToken, ?int $maxAttempts, ?array $payload): Token
    {
        return new Token([
            'userId' => (int)$user->id,
            'type' => $type,
            'tokenHash' => $type === Token::TYPE_OTP
                ? $this->_hashOtpCode($user, $rawToken)
                : hash('sha256', $rawToken),
            'expiryDate' => Carbon::now()->addSeconds($this->tokenTtl),
            'maxAttempts' => $maxAttempts,
            'payload' => $payload,
        ]);
    }

    /**
     * Returns Craft's cache component.
     *
     * @return CacheInterface
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _cache(): CacheInterface
    {
        $cache = Craft::$app->getCache();
        assert($cache instanceof CacheInterface);

        return $cache;
    }

    /**
     * Performs a fixed-cost bcrypt verification so a no-user branch cannot be
     * trivially distinguished from the real path by timing.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _equalizeTiming(): void
    {
        Craft::$app->getSecurity()->validatePassword('auth-kit-timing-equalizer', self::DUMMY_HASH);
    }

    /**
     * Atomically burns a still-usable token, re-checks the user is active, and
     * fires the surrounding consume events. Returns the user on success.
     *
     * @param Token $model the looked-up token
     * @return User|null
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _finalizeConsume(Token $model): ?User
    {
        if (!$model->isUsable()) {
            return null;
        }

        $user = Craft::$app->getUsers()->getUserById((int)$model->userId);

        if ($user === null) {
            return null;
        }

        $event = new TokenEvent(['token' => $model, 'user' => $user]);
        $this->trigger(self::EVENT_BEFORE_CONSUME_TOKEN, $event);

        if (!$event->isValid) {
            return null;
        }

        // Atomic single-use: burn the token only while it is still unconsumed.
        // A second submit or a parallel request updates zero rows and is refused.
        $affected = Db::update(
            Table::TOKENS,
            ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
            ['id' => $model->id, 'dateConsumed' => null],
        );

        if ($affected !== 1) {
            return null;
        }

        if ($user->getStatus() !== User::STATUS_ACTIVE) {
            return null;
        }

        $this->trigger(self::EVENT_AFTER_CONSUME_TOKEN, new TokenEvent(['token' => $model, 'user' => $user]));

        return $user;
    }

    /**
     * Generates a zero-padded numeric OTP code of [[otpDigits]] length.
     *
     * @return string
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _generateOtpCode(): string
    {
        $max = (10 ** $this->otpDigits) - 1;

        return str_pad((string)random_int(0, $max), $this->otpDigits, '0', STR_PAD_LEFT);
    }

    /**
     * Hashes an OTP code scoped to its user.
     *
     * A short numeric code is deterministic across the whole user base, so
     * hashing the bare code would collide on the unique `tokenHash` index the
     * moment two users hold the same code — an uncaught IntegrityException on
     * issue. Scoping the digest to the user's UID keeps every stored hash
     * distinct per user while staying reproducible on the consume side, where
     * the OTP is looked up by user and never by hash. Magic links keep the
     * bare sha256 (their 32-byte secret makes collisions impossible and IS
     * the lookup key).
     *
     * @param User $user the user the code belongs to
     * @param string $code the raw OTP code
     * @return string the scoped sha256 digest
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _hashOtpCode(User $user, string $code): string
    {
        return hash('sha256', (string)$user->uid . ':' . $code);
    }

    /**
     * Returns the mailer, defaulting to Craft's configured mailer.
     *
     * @return Mailer
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _mailer(): Mailer
    {
        if ($this->mailer === null) {
            $mailer = Craft::$app->getMailer();
            assert($mailer instanceof Mailer);
            $this->mailer = $mailer;
        }

        return $this->mailer;
    }

    /**
     * Records a failed OTP attempt against a token, burning it once the cap is
     * reached so further guesses fail closed.
     *
     * @param Token $model the token a wrong code was submitted against
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _registerFailedOtpAttempt(Token $model): void
    {
        // Atomic increment: a read-modify-write here would let an attacker
        // evade the cap by racing parallel wrong guesses (both read the same
        // count, both write +1). Incrementing in SQL keeps the counter exact.
        Db::update(
            Table::TOKENS,
            ['attempts' => new Expression('[[attempts]] + 1')],
            ['id' => $model->id, 'dateConsumed' => null],
        );

        // Burn the code once the stored count reaches the cap — evaluated
        // against the just-incremented DB value, never the stale in-memory one.
        if ($model->maxAttempts !== null) {
            Db::update(
                Table::TOKENS,
                ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
                ['and', ['id' => $model->id, 'dateConsumed' => null], ['>=', 'attempts', $model->maxAttempts]],
            );
        }
    }

    /**
     * Resolves the active user an issuance targets, applying the per-address
     * throttle and timing equalizer so unknown and ineligible addresses are
     * indistinguishable.
     *
     * @param string $email the address being issued to
     * @return User|null the active user, or null if issuance must not proceed
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _resolveIssuableUser(string $email): ?User
    {
        $email = trim($email);

        if ($email === '') {
            $this->_equalizeTiming();

            return null;
        }

        if (!$this->_withinEmailThrottle($email)) {
            return null;
        }

        $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($email);

        if ($user === null || $user->getStatus() !== User::STATUS_ACTIVE) {
            // Equalize the dominant cost of the happy path so the no-user
            // branch is not trivially distinguishable by timing.
            $this->_equalizeTiming();

            return null;
        }

        return $user;
    }

    /**
     * Persists a token row from its model.
     *
     * @param Token $token the token to store (its `id`/`uid` are populated)
     * @return bool whether the row was written
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _saveToken(Token $token): bool
    {
        if (!$token->validate()) {
            Craft::warning('Auth Kit token not saved due to validation error.', __METHOD__);

            return false;
        }

        $record = new TokenRecord();
        $record->userId = (int)$token->userId;
        $record->type = (string)$token->type;
        $record->tokenHash = (string)$token->tokenHash;
        $record->expiryDate = (string)Db::prepareDateForDb($token->expiryDate);
        $record->attempts = $token->attempts;
        $record->maxAttempts = $token->maxAttempts;
        $record->payload = $token->payload !== null ? Json::encode($token->payload) : null;
        $record->save(false);

        $token->id = (int)$record->id;
        $token->uid = $record->uid;

        return true;
    }

    /**
     * Composes and sends a token email via an Auth Kit system message.
     *
     * A delivery failure is logged but never surfaced — the token is already
     * stored, and the response must not differ for the visitor.
     *
     * @param string $key the system message key
     * @param User $user the recipient
     * @param array<string, mixed> $variables the message variables
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _sendEmail(string $key, User $user, array $variables): void
    {
        try {
            $this->_mailer()
                ->composeFromKey($key, $variables)
                ->setTo((string)$user->email)
                ->send();
        } catch (Throwable $e) {
            Craft::error("Could not send the Auth Kit email: {$e->getMessage()}", __METHOD__);
        }
    }

    /**
     * Expires every unconsumed OTP for a user, so a freshly issued code is the
     * only live one.
     *
     * @param int $userId the user whose prior OTPs are superseded
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _supersedeOtps(int $userId): void
    {
        Db::update(
            Table::TOKENS,
            ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
            ['type' => Token::TYPE_OTP, 'userId' => $userId, 'dateConsumed' => null],
        );
    }

    /**
     * Records an issuance attempt for an address and returns whether it is
     * still within the per-address throttle.
     *
     * The get-then-set on the cache is not atomic, so racing parallel
     * requests can overshoot the limit by a few — an accepted trade-off:
     * Craft's cache interface has no portable atomic increment, the overshoot
     * is bounded by the request concurrency, and the controller's per-IP
     * rate limiter compounds with this throttle.
     *
     * @param string $email the address being issued to
     * @return bool whether issuance may proceed
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _withinEmailThrottle(string $email): bool
    {
        $cache = $this->_cache();
        $key = 'authkit:token:throttle:' . hash('sha256', strtolower($email));
        $count = (int)$cache->get($key);

        if ($count >= $this->perEmailLimit) {
            return false;
        }

        $cache->set($key, $count + 1, $this->perEmailWindow);

        return true;
    }
}
