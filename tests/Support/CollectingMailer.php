<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * A mailer test double: builds real craft\mail\Message instances via the
 * inherited composeFromKey(), but captures send() instead of dispatching, so
 * tests can assert on the recipient and the issued link/code without touching
 * a real transport.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\tests\Support;

use craft\mail\Mailer;
use craft\mail\Message;
use yii\mail\MessageInterface;

final class CollectingMailer extends Mailer
{
    /**
     * @var Message[] The messages send() was asked to dispatch.
     */
    public array $sent = [];

    /**
     * @inheritdoc
     */
    public $messageClass = Message::class;

    /**
     * @inheritdoc
     */
    public function send($message): bool
    {
        if ($message instanceof Message) {
            $this->sent[] = $message;
        }

        return true;
    }

    /**
     * Returns the `code` variable from the most recently sent message.
     */
    public function lastCode(): ?string
    {
        $message = end($this->sent);

        if (!$message instanceof Message) {
            return null;
        }

        $code = $message->variables['code'] ?? null;

        return is_string($code) ? $code : null;
    }

    /**
     * Returns the `link` variable from the most recently sent message.
     */
    public function lastLink(): ?string
    {
        $message = end($this->sent);

        if (!$message instanceof Message) {
            return null;
        }

        $link = $message->variables['link'] ?? null;

        return is_string($link) ? $link : null;
    }

    /**
     * Returns the recipient addresses of the most recently sent message.
     *
     * @return array<int, string>
     */
    public function lastRecipients(): array
    {
        $message = end($this->sent);

        if (!$message instanceof MessageInterface) {
            return [];
        }

        $to = $message->getTo();

        return is_array($to) ? array_keys($to) : (array)$to;
    }
}
