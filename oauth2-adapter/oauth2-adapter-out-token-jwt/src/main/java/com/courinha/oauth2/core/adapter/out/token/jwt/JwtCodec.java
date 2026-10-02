package com.courinha.oauth2.core.adapter.out.token.jwt;

import tools.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

/**
 * A minimal JWS compact-serialization codec, HS256 only.
 *
 * <p>Deliberately hand-rolled rather than delegated to a JOSE library, and deliberately narrow:
 * one algorithm, no key management, no JWK sets. Three details matter for correctness, and each
 * is easy to get subtly wrong:
 *
 * <ul>
 *   <li>The signature covers the <em>encoded</em> header and payload, byte for byte — never a
 *       re-serialization of the parsed JSON, which would not round-trip.</li>
 *   <li>Base64 must be the URL-safe alphabet <em>without padding</em>; the default encoder emits
 *       {@code =}, and the standard alphabet emits {@code +} and {@code /}.</li>
 *   <li>Signature comparison must be constant-time, hence {@link MessageDigest#isEqual}.</li>
 * </ul>
 */
public final class JwtCodec {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /** RFC 7518 §3.2: a key of the same size as the hash output, so at least 256 bits. */
    private static final int MINIMUM_KEY_BYTES = 32;

    private final byte[] key;
    private final ObjectMapper objectMapper;

    public JwtCodec(byte[] key, ObjectMapper objectMapper) {
        if (key.length < MINIMUM_KEY_BYTES) {
            throw new IllegalArgumentException(
                    "An HS256 key must be at least %d bytes (%d bits) but was %d; a shorter key is brute-forceable"
                            .formatted(MINIMUM_KEY_BYTES, MINIMUM_KEY_BYTES * 8, key.length));
        }
        this.key = key.clone();
        this.objectMapper = objectMapper;
    }

    /** Encodes header and claims as a signed compact JWS. */
    public String encode(Map<String, Object> header, Map<String, Object> claims) {
        String signingInput = base64Url(objectMapper.writeValueAsString(header))
                + "."
                + base64Url(objectMapper.writeValueAsString(claims));
        return signingInput + "." + base64Url(sign(signingInput));
    }

    /** Verifies the signature. Not used by the token endpoint, but the counterpart to encode. */
    public boolean verify(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        String expected = base64Url(sign(parts[0] + "." + parts[1]));
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                parts[2].getBytes(StandardCharsets.US_ASCII));
    }

    private byte[] sign(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            // The signing input is base64url and '.', so ASCII bytes are exact.
            return mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Unable to compute an HS256 signature", e);
        }
    }

    private static String base64Url(String value) {
        return base64Url(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
