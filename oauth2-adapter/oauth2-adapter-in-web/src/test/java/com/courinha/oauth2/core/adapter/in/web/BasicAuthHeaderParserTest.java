package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * RFC 6749 §2.3.1 and Appendix B.
 *
 * <p>This is where naive implementations break: the credentials are form-urlencoded
 * <em>before</em> being Base64'd, so decoding has to undo two layers. A parser that only
 * Base64-decodes works for every secret made of unreserved characters and silently corrupts
 * any secret containing {@code +}, {@code %}, {@code &}, a space, or a non-ASCII character.
 */
class BasicAuthHeaderParserTest {

    private final BasicAuthHeaderParser parser = new BasicAuthHeaderParser();

    private static String basicHeader(String formEncodedCredentials) {
        return "Basic " + Base64.getEncoder()
                .encodeToString(formEncodedCredentials.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void parsesPlainCredentials() {
        Optional<BasicCredentials> parsed = parser.parse(basicHeader("demo:secret"));

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getClientId()).isEqualTo("demo");
        assertThat(parsed.get().getClientSecret()).isEqualTo("secret");
    }

    /**
     * The Appendix B golden vector. These six code points encode to exactly
     * {@code +%25%26%2B%C2%A3%E2%82%AC}, and decoding must return them unchanged.
     */
    @Test
    void roundTripsTheAppendixBGoldenVector() {
        String secret = " %&+£€";
        String encodedSecret = "+%25%26%2B%C2%A3%E2%82%AC";

        assertThat(encodePerAppendixB(secret)).isEqualTo(encodedSecret);

        Optional<BasicCredentials> parsed = parser.parse(basicHeader("demo:" + encodedSecret));

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getClientSecret()).isEqualTo(secret);
    }

    @Test
    void splitsOnTheFirstColonOnly() {
        // A secret may itself contain a colon; splitting on the last would corrupt it.
        Optional<BasicCredentials> parsed = parser.parse(basicHeader("demo:a:b:c"));

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getClientId()).isEqualTo("demo");
        assertThat(parsed.get().getClientSecret()).isEqualTo("a:b:c");
    }

    @Test
    void decodesPlusAsSpaceAndPercentEscapes() {
        Optional<BasicCredentials> parsed = parser.parse(basicHeader("demo:a+b%2Bc%25d"));

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getClientSecret()).isEqualTo("a b+c%d");
    }

    @Test
    void acceptsAnEmptySecret() {
        // §2.3.1 permits the password half to be omitted when the secret is empty.
        Optional<BasicCredentials> parsed = parser.parse(basicHeader("demo:"));

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getClientSecret()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"basic", "BASIC", "BaSiC"})
    void schemeIsCaseInsensitive(String scheme) {
        String base64 = Base64.getEncoder()
                .encodeToString("demo:secret".getBytes(StandardCharsets.UTF_8));

        assertThat(parser.parse(scheme + " " + base64)).isPresent();
    }

    @Test
    void aDifferentSchemeIsNotOursToInterpret() {
        // Not an error — the server simply has nothing to say about a Bearer header.
        assertThat(parser.parse("Bearer abc123")).isEmpty();
    }

    @Test
    void absentOrBlankHeaderYieldsNothing() {
        assertThat(parser.parse(null)).isEmpty();
        assertThat(parser.parse("   ")).isEmpty();
    }

    @Test
    void rejectsAHeaderWithNoSchemeSeparator() {
        assertThatThrownBy(() -> parser.parse("Basic"))
                .isInstanceOf(OAuth2Exception.class);
    }

    @Test
    void rejectsAnEmptyPayload() {
        assertThatThrownBy(() -> parser.parse("Basic "))
                .isInstanceOf(OAuth2Exception.class);
    }

    @Test
    void rejectsCredentialsWithNoColon() {
        assertThatThrownBy(() -> parser.parse(basicHeader("demo")))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("Malformed client credentials");
    }

    @Test
    void rejectsInvalidBase64() {
        OAuth2Exception thrown = catchThrowableOfType(
                () -> parser.parse("Basic !!!not-base64!!!"), OAuth2Exception.class);

        assertThat(thrown).isNotNull();
        assertThat(thrown.getCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST);
    }

    @Test
    void rejectsBytesThatAreNotValidUtf8() {
        // 0xFF is never valid UTF-8. This must surface as invalid_request rather than a
        // CharacterCodingException escaping the adapter or a silent U+FFFD substitution.
        String base64 = Base64.getEncoder().encodeToString(new byte[]{(byte) 0xFF, (byte) 0xFE, ':'});

        OAuth2Exception thrown = catchThrowableOfType(
                () -> parser.parse("Basic " + base64), OAuth2Exception.class);

        assertThat(thrown).isNotNull();
        assertThat(thrown.getCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST);
        assertThat(thrown.getMessage()).contains("UTF-8");
    }

    @Test
    void rejectsMalformedPercentEncoding() {
        // A bare '%' is not a valid escape sequence.
        assertThatThrownBy(() -> parser.parse(basicHeader("demo:secret%zz")))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("percent-encoding");
    }

    @Test
    void neverRendersTheSecret() {
        assertThat(new BasicCredentials("demo", "super-secret").toString())
                .doesNotContain("super-secret")
                .contains("REDACTED");
    }

    /** The client side of Appendix B, so the golden vector is derived rather than asserted. */
    private static String encodePerAppendixB(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = b & 0xFF;
            if (unsigned == ' ') {
                encoded.append('+');
            } else if (isUnreserved(unsigned)) {
                encoded.append((char) unsigned);
            } else {
                encoded.append("%%%02X".formatted(unsigned));
            }
        }
        return encoded.toString();
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_' || c == '.' || c == '~';
    }
}
