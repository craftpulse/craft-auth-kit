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

/**
 * AuditSinkInterface is the cooperation seam for audit-log persistence. An
 * emitter (Warden, Warp) records an [[AuthEvent]] through the Auth Kit `audit`
 * service; any provider plugin (e.g. Password Policy) ships a thin adapter
 * implementing this interface and registers it via
 * [[\craftpulse\authkit\services\Audit::EVENT_REGISTER_AUDIT_SINKS]]. With no
 * sink registered the service is a graceful no-op — recording is cheap and does
 * nothing.
 *
 * The contract is deliberately tiny and neutral — no plugin-detection, no
 * coupling. Two rules bind every sink:
 *
 * - A sink must ignore [[AuthEvent]] names it does not recognize, silently. Auth
 *   Kit adds names in minor releases, so a sink may receive a name newer than
 *   the vocabulary it was written against.
 * - A sink's [[handle()]] must never assume it can block the emitter: the
 *   `audit` service wraps each sink in its own try/catch, so a throwing sink is
 *   isolated and never derails the auth flow — but a sink should still fail
 *   softly (log and return) rather than rely on that backstop.
 *
 * Treat any change to this interface as a major version bump.
 *
 * @author Michael Thomas
 * @since 1.2.0
 */
interface AuditSinkInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Handles one recorded authentication event, persisting or forwarding it as
     * the sink sees fit. Unknown [[AuthEvent::$name]] values must be ignored
     * silently.
     *
     * @param AuthEvent $event the event to handle
     *
     * @author Michael Thomas
     * @since 1.2.0
     */
    public function handle(AuthEvent $event): void;
}
