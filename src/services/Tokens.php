<?php
/**
 * Auth Kit module for Craft CMS 5.x
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
use craftpulse\authkit\helpers\Duration;
use craftpulse\authkit\models\Token;
use craftpulse\authkit\records\Token as TokenRecord;
use InvalidArgumentException;
use Throwable;
use yii\base\Component;
use yii\caching\CacheInterface;
use yii\db\Expression;

/**
 * Tokens issues and consumes passwordless email credentials — magic links,
 * one-time codes (OTP), and registration links — backed by a single hashed,
 * single-use, TTL'd token store.
 *
 * Security invariants:
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
 *   response either way. Registration inverts the eligibility test — it issues
 *   for an address with no usable account yet (an unknown address, or a pending
 *   one that can still activate through the link) and refuses (equalized) an
 *   address that already maps to an active, suspended, or locked user — but the
 *   timing profile is the mirror of a login issuance, so the two branches a
 *   unified endpoint dispatches between stay indistinguishable.
 * - A login token is only honoured while its target user is genuinely active —
 *   a suspended, locked, or deactivated account cannot log back in off a stale
 *   token (a lock is checked explicitly, since `getStatus()` folds it into
 *   "active"). A registration token has no user at consume time; it proves only
 *   mailbox possession, and the consuming plugin owns the account decision.
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
 * @author CraftPulse
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
     * @var string The system message key used to compose the guest OTP email.
     *
     * @since 1.6.0
     */
    public const MESSAGE_KEY_GUEST_OTP = 'auth_kit_guest_otp';

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
     * @var string The system message key used to compose the registration email.
     *
     * @since 1.2.0
     */
    public const MESSAGE_KEY_REGISTER = 'auth_kit_register';

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
     * @since 1.0.1
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
     * @var string The site route the registration verify URL is built against.
     * Auth Kit imposes no routes — the consuming plugin registers this URL and
     * may override the route here. The raw token is appended as a
     * [[TOKEN_PARAM]] query parameter.
     *
     * @since 1.2.0
     */
    public string $registrationRoute = 'auth-kit/registration/verify';

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
     * The `origin` scopes the lookup strictly: a consumer passing its own
     * origin only ever sees tokens issued under that origin, and a legacy
     * (null-origin) consume only sees legacy tokens — a token presented at
     * the wrong consumer's endpoint is refused AND left unburned for its
     * rightful one.
     *
     * @param string $rawToken the raw token from the login URL
     * @param string|null $origin the consuming plugin's origin label, or null for legacy scope
     * @return User|null the user to log in, or null on any failure
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function consumeMagicLink(string $rawToken, ?string $origin = null): ?User
    {
        $rawToken = trim($rawToken);

        if ($rawToken === '') {
            return null;
        }

        $record = TokenRecord::findOne([
            'type' => Token::TYPE_MAGIC_LINK,
            'origin' => $origin,
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
     * The `origin` scopes the lookup strictly (see [[consumeMagicLink()]]):
     * only the newest live code issued under the consuming plugin's own
     * origin is considered.
     *
     * @param string $email the address the code was issued to
     * @param string $code the submitted OTP code
     * @param string|null $origin the consuming plugin's origin label, or null for legacy scope
     * @return User|null the user to log in, or null on any failure
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function consumeOtp(string $email, string $code, ?string $origin = null): ?User
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
            ->where(['type' => Token::TYPE_OTP, 'origin' => $origin, 'userId' => (int)$user->id, 'dateConsumed' => null])
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
     * Consumes an email-bound guest OTP code and returns whether it proved
     * control of the mailbox. No user is resolved, nothing is logged in, and no
     * session is created — the boolean is the whole result, and the consuming
     * plugin owns whatever attribution or audit trail follows.
     *
     * A guest OTP proves inbox control for an arbitrary email, so it is looked
     * up by the email's `subject` (the sha256 of the lowercased address) rather
     * than a user: the newest live guest code for the address (within `origin`)
     * is found, the submitted code is compared in constant time, and on mismatch
     * the attempt counter is incremented — once [[otpMaxAttempts]] failures
     * accrue the code is burned, mirroring the user-bound path exactly.
     *
     * Every failure branch is uniform: it performs one fixed-cost verification
     * so a caller cannot distinguish "no code was ever issued" from "a live code
     * exists but the guess was wrong" by timing.
     *
     * This fires no consume event: a guest verification is not an authentication
     * event, and Auth Kit deliberately keeps its [[\craftpulse\authkit\audit\AuthEvent]]
     * vocabulary for genuine authentications. Attribution is the consumer's story.
     *
     * @param string $email the address the code was issued to
     * @param string $code the submitted OTP code
     * @param string $origin the consuming plugin's origin label
     * @return bool whether the code proved control of the mailbox
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    public function consumeGuestOtp(string $email, string $code, string $origin): bool
    {
        $email = trim($email);
        $code = trim($code);

        if ($email === '' || $code === '') {
            $this->_equalizeTiming();

            return false;
        }

        $record = TokenRecord::find()
            ->where([
                'type' => Token::TYPE_GUEST_OTP,
                'origin' => $origin,
                'subject' => $this->_guestSubject($email),
                'dateConsumed' => null,
            ])
            ->orderBy(['id' => SORT_DESC])
            ->one();

        if (!$record instanceof TokenRecord) {
            $this->_equalizeTiming();

            return false;
        }

        $model = Token::fromRecord($record);

        if (!$model->isUsable()) {
            // Equalize this branch too: a fast return here would distinguish
            // "this address has a stale guest code" from "no code ever issued".
            $this->_equalizeTiming();

            return false;
        }

        // Constant-time comparison of the submitted code's hash against the
        // stored hash, so a wrong code is indistinguishable by timing.
        if (!hash_equals((string)$model->tokenHash, $this->_hashGuestOtpCode($email, $code))) {
            $this->_registerFailedOtpAttempt($model);

            // Equalize the wrong-code branch: its failed-attempt bookkeeping is a
            // couple of indexed single-row UPDATEs (single-digit ms), so a fast
            // return would distinguish "a live guest code exists" from "none".
            $this->_equalizeTiming();

            return false;
        }

        // Atomic single-use: burn the code only while it is still unconsumed. A
        // second submit or a parallel request updates zero rows and is refused.
        $affected = Db::update(
            Table::TOKENS,
            ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
            ['id' => $model->id, 'dateConsumed' => null],
        );

        return $affected === 1;
    }

    /**
     * Consumes a raw registration token and returns the burned token — whose
     * payload carries the address that proved mailbox possession — or null if
     * the token is unknown, expired, already used, or canceled by a handler.
     *
     * Registration tokens carry an unguessable 32-byte secret, so there is no
     * account-existence oracle to equalize: the lookup is a plain hash match,
     * exactly like a magic link. There is no user to resolve or re-check here —
     * the token proves only that its holder controls the payload's mailbox, and
     * the consuming plugin owns the account decision (create, activate, log in)
     * from the returned model.
     *
     * The `origin` scopes the lookup strictly (see [[consumeMagicLink()]]).
     *
     * @param string $rawToken the raw token from the registration URL
     * @param string|null $origin the consuming plugin's origin label, or null for legacy scope
     * @return Token|null the burned token, or null on any failure
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    public function consumeRegistration(string $rawToken, ?string $origin = null): ?Token
    {
        $rawToken = trim($rawToken);

        if ($rawToken === '') {
            return null;
        }

        $record = TokenRecord::findOne([
            'type' => Token::TYPE_REGISTER,
            'origin' => $origin,
            'tokenHash' => hash('sha256', $rawToken),
        ]);

        if ($record === null) {
            return null;
        }

        return $this->_finalizeRegistrationConsume(Token::fromRecord($record));
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
     * @param array<string, mixed> $options per-issuance overrides — `origin`, `route`, `ttl`, `perEmailLimit`, `perEmailWindow` (see [[_normalizeOptions()]])
     * @return bool whether a link was issued
     * @throws InvalidArgumentException on an unknown or malformed option
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function issueMagicLink(string $email, ?string $returnUrl = null, array $options = []): bool
    {
        $options = $this->_normalizeOptions($options, ['origin', 'route', 'ttl', 'perEmailLimit', 'perEmailWindow']);
        $user = $this->_resolveIssuableUser($email, $options);

        if ($user === null) {
            return false;
        }

        $rawToken = bin2hex(random_bytes(self::TOKEN_BYTES));
        $payload = ($returnUrl !== null && $returnUrl !== '') ? ['returnUrl' => $returnUrl] : null;

        $token = $this->_buildToken($user, Token::TYPE_MAGIC_LINK, $rawToken, null, $payload, $options);

        if (!$this->_saveToken($token)) {
            return false;
        }

        $params = [self::TOKEN_PARAM => $rawToken];

        if ($returnUrl !== null && $returnUrl !== '') {
            $params['returnUrl'] = $returnUrl;
        }

        $url = UrlHelper::siteUrl($options['route'] ?? $this->magicLinkRoute, $params);
        $this->_sendEmail(self::MESSAGE_KEY_MAGIC_LINK, (string)$user->email, [
            'link' => $url,
            'user' => $user,
            'expiresIn' => $this->_expiresIn($options),
        ]);

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
     * @param array<string, mixed> $options per-issuance overrides — `origin`, `ttl`, `digits`, `maxAttempts`, `perEmailLimit`, `perEmailWindow` (see [[_normalizeOptions()]])
     * @return bool whether a code was issued
     * @throws InvalidArgumentException on an unknown or malformed option
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function issueOtp(string $email, array $options = []): bool
    {
        $options = $this->_normalizeOptions($options, ['origin', 'ttl', 'digits', 'maxAttempts', 'perEmailLimit', 'perEmailWindow']);
        $user = $this->_resolveIssuableUser($email, $options);

        if ($user === null) {
            return false;
        }

        // Supersede any prior unconsumed OTP for this user (within the same
        // origin) so only the newest code is live — an attacker cannot keep an
        // old code's attempt budget, and one consumer cannot burn another's code.
        $this->_supersedeOtps((int)$user->id, $options['origin'] ?? null);

        $code = $this->_generateOtpCode($options['digits'] ?? null);
        $token = $this->_buildToken($user, Token::TYPE_OTP, $code, $options['maxAttempts'] ?? $this->otpMaxAttempts, null, $options);

        if (!$this->_saveToken($token)) {
            return false;
        }

        $this->_sendEmail(self::MESSAGE_KEY_OTP, (string)$user->email, [
            'code' => $code,
            'user' => $user,
            'expiresIn' => $this->_expiresIn($options),
        ]);

        $this->trigger(self::EVENT_AFTER_ISSUE_TOKEN, new TokenEvent(['token' => $token, 'user' => $user]));

        return true;
    }

    /**
     * Issues an email-bound guest OTP code to any syntactically valid email and
     * emails it. Unlike [[issueOtp()]], the address need not map to any user —
     * the code proves control of an arbitrary mailbox, and the recipient never
     * becomes a user, is never logged in, and gets no session. Issuing a new
     * code supersedes (expires) any prior unconsumed guest code for the same
     * email within the same origin.
     *
     * Returns nothing: the issue path never reveals whether a code was sent. An
     * empty, malformed, or throttled address is dropped silently — there is no
     * account to enumerate (any valid mailbox is issuable), so no timing
     * equalizer is needed here, unlike the user-bound issuance which must hide
     * account existence.
     *
     * This fires [[EVENT_AFTER_ISSUE_TOKEN]] with a null user (like a
     * registration issuance), a token-bookkeeping signal only. It emits no
     * [[\craftpulse\authkit\audit\AuthEvent]]: proving mailbox control is not an
     * authentication, and attribution is the consuming plugin's audit story.
     *
     * @param string $email the address to send a code to
     * @param string $origin the consuming plugin's origin label
     * @param array<string, mixed> $options per-issuance overrides — `ttl`, `digits`, `maxAttempts`, `perEmailLimit`, `perEmailWindow` (see [[_normalizeOptions()]])
     * @throws InvalidArgumentException on an unknown or malformed option, or a malformed origin
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    public function issueGuestOtp(string $email, string $origin, array $options = []): void
    {
        $options = $this->_normalizeOptions($options, ['ttl', 'digits', 'maxAttempts', 'perEmailLimit', 'perEmailWindow']);

        if ($origin === '' || strlen($origin) > 32) {
            throw new InvalidArgumentException('Guest OTP "origin" must be 1-32 characters.');
        }

        // The origin travels with the throttle and the token row.
        $options['origin'] = $origin;
        $email = trim($email);

        // Any syntactically valid mailbox is issuable, so a bad address reveals
        // nothing worth equalizing — drop it silently.
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return;
        }

        if (!$this->_withinEmailThrottle($email, $options)) {
            return;
        }

        // Supersede any prior unconsumed guest code for this email (within the
        // same origin) so only the newest is live — an attacker cannot keep an
        // old code's attempt budget, and one consumer cannot burn another's.
        $this->_supersedeGuestOtps($email, $origin);

        $code = $this->_generateOtpCode($options['digits'] ?? null);
        $token = $this->_buildGuestToken($email, $code, $options['maxAttempts'] ?? $this->otpMaxAttempts, $options);

        if (!$this->_saveToken($token)) {
            return;
        }

        $this->_sendEmail(self::MESSAGE_KEY_GUEST_OTP, $email, [
            'code' => $code,
            'email' => $email,
            'expiresIn' => $this->_expiresIn($options),
        ]);

        $this->trigger(self::EVENT_AFTER_ISSUE_TOKEN, new TokenEvent(['token' => $token, 'user' => null]));
    }

    /**
     * Issues a registration link for an email address and emails it, when the
     * address has no account yet. Issuing a link mints no user row — the address
     * lives in the token payload until the consuming plugin creates the account
     * at verify time.
     *
     * Registration is the near-inverse of a login issuance: it proceeds for an
     * address with no usable account yet — an unknown address, or a pending one
     * whose holder can still finish activating through the signup link — and
     * refuses an address that already maps to an active, suspended, or locked
     * user (the caller branches an active address to [[issueMagicLink()]]). The
     * refusal is equalized so it is indistinguishable by timing from the
     * unknown-address path, which pays its cost on the token write and email send.
     *
     * Returns whether a link was actually issued — but callers facing the
     * public must respond identically regardless, to stay enumeration-safe.
     *
     * @param string $email the address to send a registration link to
     * @param string|null $returnUrl the validated URL to return to after signup
     * @param array<string, mixed> $options per-issuance overrides — `origin`, `route`, `ttl`, `perEmailLimit`, `perEmailWindow` (see [[_normalizeOptions()]])
     * @return bool whether a link was issued
     * @throws InvalidArgumentException on an unknown or malformed option
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    public function issueRegistration(string $email, ?string $returnUrl = null, array $options = []): bool
    {
        $options = $this->_normalizeOptions($options, ['origin', 'route', 'ttl', 'perEmailLimit', 'perEmailWindow']);
        $email = trim($email);

        if ($email === '') {
            $this->_equalizeTiming();

            return false;
        }

        // A malformed address can never map to an account, so refuse it through
        // the same equalized path an existing-active address takes — the caller
        // must not be able to tell a bad address from a taken one.
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->_equalizeTiming();

            return false;
        }

        if (!$this->_withinEmailThrottle($email, $options)) {
            return false;
        }

        $existing = Craft::$app->getUsers()->getUserByUsernameOrEmail($email);

        // Registration proceeds for an address with no usable account yet — an
        // unknown address, or a pending one whose holder can still finish
        // activating through the signup link (a unified endpoint routes an
        // already-active address to a login issuance instead). Any account that
        // is active, suspended, or locked is refused through the equalized path,
        // so this branch stays indistinguishable by timing from the
        // unknown-address one, which pays its cost on the token write and email.
        if ($existing !== null && $existing->getStatus() !== User::STATUS_PENDING) {
            $this->_equalizeTiming();

            return false;
        }

        $rawToken = bin2hex(random_bytes(self::TOKEN_BYTES));
        $payload = ['email' => $email];

        if ($returnUrl !== null && $returnUrl !== '') {
            $payload['returnUrl'] = $returnUrl;
        }

        $token = $this->_buildRegistrationToken($rawToken, $payload, $options);

        if (!$this->_saveToken($token)) {
            return false;
        }

        $params = [self::TOKEN_PARAM => $rawToken];

        if ($returnUrl !== null && $returnUrl !== '') {
            $params['returnUrl'] = $returnUrl;
        }

        $url = UrlHelper::siteUrl($options['route'] ?? $this->registrationRoute, $params);
        $this->_sendEmail(self::MESSAGE_KEY_REGISTER, $email, [
            'link' => $url,
            'email' => $email,
            'expiresIn' => $this->_expiresIn($options),
        ]);

        $this->trigger(self::EVENT_AFTER_ISSUE_TOKEN, new TokenEvent(['token' => $token, 'user' => null]));

        return true;
    }

    /**
     * Deletes every expired token. Safe to run on a schedule; consumed tokens
     * are pruned once their expiry passes.
     *
     * @return int the number of rows deleted
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function purgeExpiredTokens(): int
    {
        return Db::delete(Table::TOKENS, ['<', 'expiryDate', Db::prepareDateForDb(Carbon::now())]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Validates and normalizes a per-issuance options array.
     *
     * Options override the shared service defaults for one issuance, so two
     * consuming plugins never depend on mutable singleton state: `origin`
     * (?string, ≤32 — the consumer's label, stored on the token and matched
     * strictly at consume time), `route` (?string — the verify route for the
     * emailed URL), `ttl`, `digits`, `maxAttempts`, `perEmailLimit`,
     * `perEmailWindow` (positive ints). Unknown keys and malformed values are
     * refused loudly — this is a security surface, not a config grab-bag.
     *
     * @param array<string, mixed> $options the caller-supplied options
     * @param array<int, string> $allowed the keys this issuance type accepts
     * @return array<string, mixed> the validated options
     * @throws InvalidArgumentException on an unknown key or malformed value
     *
     * @author CraftPulse
     * @since 1.4.0
     */
    private function _normalizeOptions(array $options, array $allowed): array
    {
        foreach (array_keys($options) as $key) {
            if (!in_array($key, $allowed, true)) {
                throw new InvalidArgumentException("Unknown token issuance option \"{$key}\".");
            }
        }

        foreach (['origin', 'route'] as $key) {
            if (array_key_exists($key, $options) && !is_string($options[$key])) {
                throw new InvalidArgumentException("Token issuance option \"{$key}\" must be a string.");
            }
        }

        if (isset($options['origin']) && ($options['origin'] === '' || strlen($options['origin']) > 32)) {
            throw new InvalidArgumentException('Token issuance option "origin" must be 1-32 characters.');
        }

        foreach (['ttl', 'digits', 'maxAttempts', 'perEmailLimit', 'perEmailWindow'] as $key) {
            if (array_key_exists($key, $options) && (!is_int($options[$key]) || $options[$key] < 1)) {
                throw new InvalidArgumentException("Token issuance option \"{$key}\" must be a positive integer.");
            }
        }

        return $options;
    }

    /**
     * Builds an unsaved registration token — user-less, its target email held
     * in the payload.
     *
     * The raw token is a 32-byte secret hashed bare (like a magic link): the
     * secret is unguessable, so there is no per-user scoping to do and the hash
     * is the lookup key.
     *
     * @param string $rawToken the raw token whose hash is stored
     * @param array<string, mixed> $payload the issuance metadata (email, returnUrl)
     * @param array<string, mixed> $options the normalized issuance options
     * @return Token
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    private function _buildRegistrationToken(string $rawToken, array $payload, array $options = []): Token
    {
        return new Token([
            'userId' => null,
            'type' => Token::TYPE_REGISTER,
            'origin' => $options['origin'] ?? null,
            'tokenHash' => hash('sha256', $rawToken),
            'expiryDate' => Carbon::now()->addSeconds($options['ttl'] ?? $this->tokenTtl),
            'maxAttempts' => null,
            'payload' => $payload,
        ]);
    }

    /**
     * Builds an unsaved email-bound guest OTP token — user-less, keyed by the
     * email's `subject` with the code hashed under the same email scope.
     *
     * The code is short and guessable, so its stored hash is scoped to the email
     * (like the user-bound OTP scopes to the user's UID) — two mailboxes holding
     * the same code produce distinct hashes and never collide on the unique
     * `tokenHash` index. The `subject` is the lookup key the consume path finds
     * the row by, before the code is compared.
     *
     * @param string $email the mailbox the code proves control of
     * @param string $code the raw OTP code whose scoped hash is stored
     * @param int|null $maxAttempts the failed-attempt cap, or null for none
     * @param array<string, mixed> $options the normalized issuance options
     * @return Token
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    private function _buildGuestToken(string $email, string $code, ?int $maxAttempts, array $options = []): Token
    {
        return new Token([
            'userId' => null,
            'type' => Token::TYPE_GUEST_OTP,
            'origin' => $options['origin'] ?? null,
            'subject' => $this->_guestSubject($email),
            'tokenHash' => $this->_hashGuestOtpCode($email, $code),
            'expiryDate' => Carbon::now()->addSeconds($options['ttl'] ?? $this->tokenTtl),
            'maxAttempts' => $maxAttempts,
            'payload' => null,
        ]);
    }

    /**
     * Builds an unsaved token model for a user.
     *
     * @param User $user the target user
     * @param string $type the token type
     * @param string $rawToken the raw token whose hash is stored
     * @param int|null $maxAttempts the failed-attempt cap, or null for none
     * @param array<string, mixed>|null $payload arbitrary issuance metadata
     * @param array<string, mixed> $options the normalized issuance options
     * @return Token
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _buildToken(User $user, string $type, string $rawToken, ?int $maxAttempts, ?array $payload, array $options = []): Token
    {
        return new Token([
            'userId' => (int)$user->id,
            'type' => $type,
            'origin' => $options['origin'] ?? null,
            'tokenHash' => $type === Token::TYPE_OTP
                ? $this->_hashOtpCode($user, $rawToken)
                : hash('sha256', $rawToken),
            'expiryDate' => Carbon::now()->addSeconds($options['ttl'] ?? $this->tokenTtl),
            'maxAttempts' => $maxAttempts,
            'payload' => $payload,
        ]);
    }

    /**
     * Returns Craft's cache component.
     *
     * @return CacheInterface
     *
     * @author CraftPulse
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
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _equalizeTiming(): void
    {
        Craft::$app->getSecurity()->validatePassword('auth-kit-timing-equalizer', self::DUMMY_HASH);
    }

    /**
     * Formats the lifetime an issuance is about to use as the phrase its email
     * states — "15 minutes", "1 hour", "1 day".
     *
     * It reads the same `ttl` the token row is written with, falling back to
     * [[$tokenTtl]] exactly as [[_buildToken()]] does, so the recipient is told
     * the lifetime their credential actually has: a consuming plugin passing its
     * own TTL per issuance has that value quoted back, never a shared default.
     *
     * @param array<string, mixed> $options the normalized per-issuance options
     * @return string
     *
     * @author CraftPulse
     * @since 1.8.0
     */
    private function _expiresIn(array $options): string
    {
        return Duration::human((int)($options['ttl'] ?? $this->tokenTtl));
    }

    /**
     * Atomically burns a still-usable token, re-checks the user is active and
     * not locked, and fires the surrounding consume events. Returns the user on
     * success.
     *
     * @param Token $model the looked-up token
     * @return User|null
     *
     * @author CraftPulse
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

        // getStatus() folds a locked account into "active", so the lock is
        // checked explicitly — a stale login token must not log in behind an
        // account lockout. The burn above stays and the login is refused, mirror
        // of the suspended path.
        if ($user->locked) {
            return null;
        }

        $this->trigger(self::EVENT_AFTER_CONSUME_TOKEN, new TokenEvent(['token' => $model, 'user' => $user]));

        return $user;
    }

    /**
     * Atomically burns a still-usable registration token and fires the
     * surrounding consume events with a null user. Returns the burned token on
     * success.
     *
     * There is no user to resolve or re-check — a registration token proves only
     * mailbox possession, and the consuming plugin owns the account decision.
     * The before-consume event stays cancelable so a handler can refuse the
     * signup before the token is burned.
     *
     * @param Token $model the looked-up token
     * @return Token|null
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    private function _finalizeRegistrationConsume(Token $model): ?Token
    {
        if (!$model->isUsable()) {
            return null;
        }

        $event = new TokenEvent(['token' => $model, 'user' => null]);
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

        $model->dateConsumed = Carbon::now();

        $this->trigger(self::EVENT_AFTER_CONSUME_TOKEN, new TokenEvent(['token' => $model, 'user' => null]));

        return $model;
    }

    /**
     * Generates a zero-padded numeric OTP code of [[otpDigits]] length.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _generateOtpCode(?int $digits = null): string
    {
        $digits ??= $this->otpDigits;
        $max = (10 ** $digits) - 1;

        return str_pad((string)random_int(0, $max), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Computes the lookup subject for a guest OTP — the sha256 of the lowercased,
     * trimmed email. Never the raw address: the table stores no guest email, so
     * attribution stays the consuming plugin's concern.
     *
     * @param string $email the mailbox the code is bound to
     * @return string the sha256 subject digest
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    private function _guestSubject(string $email): string
    {
        return hash('sha256', strtolower(trim($email)));
    }

    /**
     * Hashes a guest OTP code scoped to its email.
     *
     * A short numeric code is deterministic across every mailbox, so hashing the
     * bare code would collide on the unique `tokenHash` index the moment two
     * emails hold the same code. Scoping the digest to the lowercased email keeps
     * every stored hash distinct while staying reproducible on the consume side,
     * where the code is looked up by `subject` and never by hash.
     *
     * @param string $email the mailbox the code belongs to
     * @param string $code the raw OTP code
     * @return string the scoped sha256 digest
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    private function _hashGuestOtpCode(string $email, string $code): string
    {
        return hash('sha256', strtolower(trim($email)) . ':' . $code);
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
     * @author CraftPulse
     * @since 1.0.1
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
     * @author CraftPulse
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
     * @author CraftPulse
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
     * @param array<string, mixed> $options the normalized issuance options (throttle overrides)
     * @return User|null the active user, or null if issuance must not proceed
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _resolveIssuableUser(string $email, array $options = []): ?User
    {
        $email = trim($email);

        if ($email === '') {
            $this->_equalizeTiming();

            return null;
        }

        if (!$this->_withinEmailThrottle($email, $options)) {
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
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _saveToken(Token $token): bool
    {
        if (!$token->validate()) {
            Craft::warning('Auth Kit token not saved due to validation error.', __METHOD__);

            return false;
        }

        $record = new TokenRecord();
        $record->userId = $token->userId !== null ? (int)$token->userId : null;
        $record->type = (string)$token->type;
        $record->tokenHash = (string)$token->tokenHash;
        $record->expiryDate = (string)Db::prepareDateForDb($token->expiryDate);
        $record->attempts = $token->attempts;
        $record->maxAttempts = $token->maxAttempts;
        $record->origin = $token->origin;
        $record->subject = $token->subject;
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
     * @param string $email the recipient address
     * @param array<string, mixed> $variables the message variables
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _sendEmail(string $key, string $email, array $variables): void
    {
        try {
            $this->_mailer()
                ->composeFromKey($key, $variables)
                ->setTo($email)
                ->send();
        } catch (Throwable $e) {
            Craft::error("Could not send the Auth Kit email: {$e->getMessage()}", __METHOD__);
        }
    }

    /**
     * Expires every unconsumed guest OTP for an email, so a freshly issued code
     * is the only live one.
     *
     * @param string $email the mailbox whose prior guest codes are superseded
     * @param string $origin the issuing origin — supersede stays within it
     *
     * @author CraftPulse
     * @since 1.6.0
     */
    private function _supersedeGuestOtps(string $email, string $origin): void
    {
        Db::update(
            Table::TOKENS,
            ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
            ['type' => Token::TYPE_GUEST_OTP, 'origin' => $origin, 'subject' => $this->_guestSubject($email), 'dateConsumed' => null],
        );
    }

    /**
     * Expires every unconsumed OTP for a user, so a freshly issued code is the
     * only live one.
     *
     * @param int $userId the user whose prior OTPs are superseded
     * @param string|null $origin the issuing origin — supersede stays within it
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _supersedeOtps(int $userId, ?string $origin = null): void
    {
        Db::update(
            Table::TOKENS,
            ['dateConsumed' => Db::prepareDateForDb(Carbon::now())],
            ['type' => Token::TYPE_OTP, 'origin' => $origin, 'userId' => $userId, 'dateConsumed' => null],
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
     * @param array<string, mixed> $options the normalized issuance options (`origin`, `perEmailLimit`, `perEmailWindow`)
     * @return bool whether issuance may proceed
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _withinEmailThrottle(string $email, array $options = []): bool
    {
        $cache = $this->_cache();

        // The bucket is origin-scoped so one consumer exhausting its budget
        // never starves another; the mailbox's total exposure is the sum of
        // the (small) per-consumer budgets.
        $origin = $options['origin'] ?? null;
        $key = 'authkit:token:throttle:' . ($origin !== null ? "{$origin}:" : '') . hash('sha256', strtolower($email));
        $count = (int)$cache->get($key);

        if ($count >= ($options['perEmailLimit'] ?? $this->perEmailLimit)) {
            return false;
        }

        $cache->set($key, $count + 1, $options['perEmailWindow'] ?? $this->perEmailWindow);

        return true;
    }
}
