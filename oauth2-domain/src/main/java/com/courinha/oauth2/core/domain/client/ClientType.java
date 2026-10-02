package com.courinha.oauth2.core.domain.client;

/**
 * RFC 6749 §2.1. A confidential client can hold credentials securely; a public client cannot,
 * and so cannot be trusted to keep a secret or to authenticate on its own.
 */
public enum ClientType {

    /** Runs on a protected server; holds a secret and authenticates at the token endpoint. */
    CONFIDENTIAL,

    /** Runs where secrets cannot be kept (a browser, a device); has no secret. */
    PUBLIC
}
