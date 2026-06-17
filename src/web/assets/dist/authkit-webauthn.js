/**
 * Auth Kit — front-end passwordless helpers (WebAuthn + magic links).
 *
 * A dependency-free reference client for the two passkey ceremonies and the
 * magic-link request. Enrollment talks to the consuming plugin's own endpoints
 * (which run behind a login + the recent-auth gate); login talks to Craft
 * core's anonymous passkey endpoints. Copy and adapt this to your front end.
 *
 * Exposed as `window.AuthKit`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */
(function (window) {
  'use strict';

  // Base64url <-> ArrayBuffer
  // ===========================================================================

  function base64urlToBuffer(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Option / credential (de)serialization to the standard WebAuthn JSON shape
  // ===========================================================================

  function decodeCreationOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (Array.isArray(options.excludeCredentials)) {
      options.excludeCredentials = options.excludeCredentials.map((cred) => ({
        ...cred,
        id: base64urlToBuffer(cred.id),
      }));
    }
    return options;
  }

  function decodeRequestOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    if (Array.isArray(options.allowCredentials)) {
      options.allowCredentials = options.allowCredentials.map((cred) => ({
        ...cred,
        id: base64urlToBuffer(cred.id),
      }));
    }
    return options;
  }

  function encodeAttestation(credential) {
    const response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        attestationObject: bufferToBase64url(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : [],
      },
    };
  }

  function encodeAssertion(credential) {
    const response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        authenticatorData: bufferToBase64url(response.authenticatorData),
        signature: bufferToBase64url(response.signature),
        userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
      },
    };
  }

  // Transport
  // ===========================================================================

  async function postJson(url, body, csrfToken) {
    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    };
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body || {}),
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    return {ok: res.ok, status: res.status, data};
  }

  // Public API
  // ===========================================================================

  function supportsWebAuthn() {
    return typeof window.PublicKeyCredential !== 'undefined';
  }

  /**
   * Runs the enrollment ceremony against the consuming plugin's endpoints.
   *
   * @param {Object} opts
   * @param {string} opts.optionsUrl    creation-options endpoint
   * @param {string} opts.verifyUrl     verify-creation endpoint
   * @param {string} [opts.csrfToken]   CSRF token
   * @param {string} [opts.credentialName]
   * @returns {Promise<Object>} the verify response payload
   */
  async function enrollPasskey(opts) {
    if (!supportsWebAuthn()) {
      throw new Error('This browser does not support passkeys.');
    }

    const optionsRes = await postJson(opts.optionsUrl, {}, opts.csrfToken);
    if (!optionsRes.ok) {
      const error = new Error(optionsRes.data.message || 'Could not start passkey enrollment.');
      error.reauthRequired = !!optionsRes.data.reauthRequired;
      throw error;
    }

    const publicKey = decodeCreationOptions(JSON.parse(optionsRes.data.options));
    const credential = await navigator.credentials.create({publicKey});

    const verifyRes = await postJson(
      opts.verifyUrl,
      {
        credentials: JSON.stringify(encodeAttestation(credential)),
        credentialName: opts.credentialName || null,
      },
      opts.csrfToken
    );

    if (!verifyRes.ok) {
      throw new Error(verifyRes.data.message || 'Passkey enrollment failed.');
    }

    return verifyRes.data;
  }

  /**
   * Runs the login ceremony against Craft core's anonymous passkey endpoints.
   *
   * @param {Object} opts
   * @param {string} opts.optionsUrl    core actions/auth/passkey-request-options
   * @param {string} opts.loginUrl      core actions/users/login-with-passkey
   * @param {string} [opts.csrfToken]
   * @returns {Promise<Object>} the login response payload
   */
  async function loginWithPasskey(opts) {
    if (!supportsWebAuthn()) {
      throw new Error('This browser does not support passkeys.');
    }

    const optionsRes = await postJson(opts.optionsUrl, {}, opts.csrfToken);
    if (!optionsRes.ok) {
      throw new Error(optionsRes.data.message || 'Could not start passkey login.');
    }

    const publicKey = decodeRequestOptions(JSON.parse(optionsRes.data.options));
    const credential = await navigator.credentials.get({publicKey});

    const loginRes = await postJson(
      opts.loginUrl,
      {response: JSON.stringify(encodeAssertion(credential))},
      opts.csrfToken
    );

    if (!loginRes.ok) {
      throw new Error(loginRes.data.message || 'Passkey login failed.');
    }

    return loginRes.data;
  }

  /**
   * Requests a magic link for an email address. The response is intentionally
   * identical whether or not an account exists.
   *
   * @param {Object} opts
   * @param {string} opts.sendUrl       magic-link send endpoint
   * @param {string} opts.email
   * @param {string} [opts.returnUrl]
   * @param {string} [opts.csrfToken]
   * @returns {Promise<Object>} the send response payload
   */
  async function requestMagicLink(opts) {
    const res = await postJson(
      opts.sendUrl,
      {email: opts.email, returnUrl: opts.returnUrl || null},
      opts.csrfToken
    );
    return res.data;
  }

  window.AuthKit = {
    supportsWebAuthn,
    enrollPasskey,
    loginWithPasskey,
    requestMagicLink,
  };
})(window);
