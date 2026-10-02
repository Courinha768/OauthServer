package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2Exception;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Parses the {@code Authorization: Basic} header per RFC 6749 §2.3.1 and Appendix B.
 *
 * <p>This is the most commonly mis-implemented part of the whole protocol. Appendix B says the
 * client encodes {@code client_id} and {@code client_secret} with the
 * {@code application/x-www-form-urlencoded} algorithm <em>first</em>, then uses those encoded
 * values as the Basic username and password. So decoding has to undo both layers, in order:
 *
 * <ol>
 *   <li>Base64-decode, then interpret the bytes as UTF-8.</li>
 *   <li>Split on the <em>first</em> colon only — a secret may itself contain one.</li>
 *   <li>Form-decode each half, which turns {@code +} back into a space and {@code %XX} into
 *       its byte.</li>
 * </ol>
 *
 * <p>Skipping the third step works for every secret made only of unreserved characters, and
 * silently corrupts any secret containing {@code +}, {@code %}, {@code &}, a space, or a
 * non-ASCII character.
 */
public final class BasicAuthHeaderParser {

    private static final String SCHEME = "Basic";

    /**
     * @param authorizationHeader the raw header value, possibly {@code null}
     * @return the credentials, or empty when the header is absent or uses another scheme
     * @throws OAuth2Exception {@code invalid_request} if the header is present but malformed
     */
    public Optional<BasicCredentials> parse(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return Optional.empty();
        }

        int separator = authorizationHeader.indexOf(' ');
        if (separator < 0) {
            throw OAuth2Exception.invalidRequest("Malformed Authorization header");
        }

        // §2.3.1 names the scheme "Basic"; RFC 7235 makes the scheme token case-insensitive.
        if (!SCHEME.equalsIgnoreCase(authorizationHeader.substring(0, separator))) {
            // Some other scheme (Bearer, say). Not ours to interpret, and not an error.
            return Optional.empty();
        }

        String encoded = authorizationHeader.substring(separator + 1).trim();
        if (encoded.isEmpty()) {
            throw OAuth2Exception.invalidRequest("Malformed Authorization header");
        }

        String decoded = decodeBase64AsUtf8(encoded);

        int colon = decoded.indexOf(':');
        if (colon < 0) {
            throw OAuth2Exception.invalidRequest(
                    "Malformed client credentials in Authorization header");
        }

        return Optional.of(new BasicCredentials(
                formUrlDecode(decoded.substring(0, colon)),
                // An empty secret is legal, so the substring may legitimately be empty.
                formUrlDecode(decoded.substring(colon + 1))));
    }

    private static String decodeBase64AsUtf8(String encoded) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw OAuth2Exception.invalidRequest("Authorization header is not valid Base64");
        }

        // Strict decoding: a byte sequence that is not valid UTF-8 must be reported as a bad
        // request, not silently replaced with U+FFFD.
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw OAuth2Exception.invalidRequest("Authorization header is not valid UTF-8");
        }
    }

    private static String formUrlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw OAuth2Exception.invalidRequest(
                    "Malformed percent-encoding in client credentials");
        }
    }
}
