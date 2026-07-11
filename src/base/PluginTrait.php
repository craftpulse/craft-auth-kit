<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\base;

use Craft;
use craft\events\RegisterEmailMessagesEvent;
use craft\models\SystemMessage;
use craft\services\Gc;
use craft\services\SystemMessages;
use craft\web\twig\variables\CraftVariable;
use craft\web\User as WebUser;
use craftpulse\authkit\services\Tokens;
use craftpulse\authkit\variables\AuthKitVariable;
use yii\base\Event;

/**
 * PluginTrait owns Auth Kit's event listeners and plugin lifecycle wiring,
 * keeping the main plugin class a thin orchestrator.
 *
 * Auth Kit imposes no URL rules and ships no controllers — consuming plugins
 * own their own route registration. What it does wire is the recent-auth stamp
 * on login, the `craft.authKit` Twig variable, and the editable system
 * messages backing the magic-link and OTP emails.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
trait PluginTrait
{
    // Private Methods
    // =========================================================================

    /**
     * Attaches Auth Kit's event handlers.
     *
     * Called from `AuthKit::init()` once the application has fully initialized.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _attachEventHandlers(): void
    {
        $this->_registerGarbageCollection();
        $this->_registerRecentAuthTracking();
        $this->_registerSystemMessages();
        $this->_registerVariable();
    }

    /**
     * Prunes expired tokens on Craft's garbage-collection pass.
     *
     * Auth Kit owns the `authkit_tokens` table, so it owns the cleanup —
     * consuming plugins (Warden, Warp) get it for free and never wire their
     * own scheduler. `craft\services\Gc::EVENT_RUN` fires on every GC run
     * (`php craft gc`, and probabilistically during requests) with a base
     * `yii\base\Event` — there is no dedicated event class. Expired tokens are
     * already unusable, so deleting them is safe and needs no retention window.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _registerGarbageCollection(): void
    {
        Event::on(
            Gc::class,
            Gc::EVENT_RUN,
            function(): void {
                $this->getTokens()->purgeExpiredTokens();
            },
        );
    }

    /**
     * Tracks the last authentication time so the passkeys service's recent-auth
     * gate works for passwordless users.
     *
     * Stamping on every successful login — magic link, OTP, passkey, or
     * password — means any authentication path refreshes the window
     * consistently. The session is regenerated before this fires, so the stamp
     * lands in the fresh session.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _registerRecentAuthTracking(): void
    {
        Event::on(
            WebUser::class,
            WebUser::EVENT_AFTER_LOGIN,
            function(): void {
                $this->getPasskeys()->stampRecentAuth();
            },
        );
    }

    /**
     * Registers Auth Kit's editable system messages — the magic-link, OTP, and
     * registration emails. Subject and body are Twig, rendered with the
     * variables the tokens service passes to `composeFromKey()`: `link` + `user`
     * for magic links, `code` + `user` for OTP, and `link` + `email` for
     * registration (no user exists yet, so the copy addresses the visitor
     * without a friendly name).
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _registerSystemMessages(): void
    {
        Event::on(
            SystemMessages::class,
            SystemMessages::EVENT_REGISTER_MESSAGES,
            static function(RegisterEmailMessagesEvent $event): void {
                $event->messages[] = new SystemMessage([
                    'key' => Tokens::MESSAGE_KEY_MAGIC_LINK,
                    'heading' => Craft::t('auth-kit', 'When someone requests a magic sign-in link:'),
                    'subject' => Craft::t('auth-kit', 'Your sign-in link'),
                    'body' => Craft::t('auth-kit', "Hi {{ user.friendlyName }},\n\nUse the link below to sign in. It expires shortly and can be used only once.\n\n{{ link }}\n\nIf you didn’t request this, you can safely ignore this email."),
                ]);

                $event->messages[] = new SystemMessage([
                    'key' => Tokens::MESSAGE_KEY_OTP,
                    'heading' => Craft::t('auth-kit', 'When someone requests a one-time sign-in code:'),
                    'subject' => Craft::t('auth-kit', 'Your sign-in code'),
                    'body' => Craft::t('auth-kit', "Hi {{ user.friendlyName }},\n\nYour one-time sign-in code is:\n\n{{ code }}\n\nIt expires shortly and can be used only once. If you didn’t request this, you can safely ignore this email."),
                ]);

                $event->messages[] = new SystemMessage([
                    'key' => Tokens::MESSAGE_KEY_REGISTER,
                    'heading' => Craft::t('auth-kit', 'When someone requests a link to finish signing up:'),
                    'subject' => Craft::t('auth-kit', 'Finish setting up your account'),
                    'body' => Craft::t('auth-kit', "Hi,\n\nUse the link below to finish setting up your account. It expires shortly and can be used only once.\n\n{{ link }}\n\nIf you didn’t request this, you can safely ignore this email."),
                ]);
            },
        );
    }

    /**
     * Registers the `craft.authKit` Twig variable.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _registerVariable(): void
    {
        Event::on(
            CraftVariable::class,
            CraftVariable::EVENT_INIT,
            static function(Event $event): void {
                /** @var CraftVariable $variable */
                $variable = $event->sender;
                $variable->set('authKit', AuthKitVariable::class);
            },
        );
    }
}
