package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.application.port.in.ClientCredentialsCommand;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class TokenRequestParserTest {

    private final TokenRequestParser parser = new TokenRequestParser(new BasicAuthHeaderParser());

    private static MultiValueMap<String, String> form(String... keyValues) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            parameters.add(keyValues[i], keyValues[i + 1]);
        }
        return parameters;
    }

    private static String basicHeader(String credentials) {
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static OAuth2Exception assertRejected(MultiValueMap<String, String> parameters,
                                                  String authorization,
                                                  boolean credentialsInQuery) {
        OAuth2Exception thrown = catchThrowableOfType(
                () -> new TokenRequestParser(new BasicAuthHeaderParser())
                        .parse(parameters, authorization, credentialsInQuery),
                OAuth2Exception.class);
        assertThat(thrown).isNotNull();
        assertThat(thrown.getCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST);
        return thrown;
    }

    @Test
    void readsBasicCredentialsFromTheHeader() {
        ClientCredentialsCommand command = parser.parse(
                form("grant_type", "client_credentials", "scope", "read"),
                basicHeader("demo:secret"),
                false);

        assertThat(command.getClientId()).isEqualTo("demo");
        assertThat(command.getClientSecret()).isEqualTo("secret");
        assertThat(command.getPresentedMethod()).isEqualTo(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        assertThat(command.getGrantType()).isEqualTo("client_credentials");
        assertThat(command.getScope()).isEqualTo("read");
    }

    @Test
    void readsBodyCredentialsWhenThereIsNoHeader() {
        ClientCredentialsCommand command = parser.parse(
                form("grant_type", "client_credentials", "client_id", "demo", "client_secret", "secret"),
                null,
                false);

        assertThat(command.getClientId()).isEqualTo("demo");
        assertThat(command.getClientSecret()).isEqualTo("secret");
        assertThat(command.getPresentedMethod()).isEqualTo(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
    }

    @Test
    void reportsNoCredentialsAsNone() {
        ClientCredentialsCommand command = parser.parse(form("grant_type", "client_credentials"), null, false);

        assertThat(command.getClientId()).isNull();
        assertThat(command.getPresentedMethod()).isEqualTo(TokenEndpointAuthMethod.NONE);
    }

    @Test
    void aBareClientIdBesideABasicHeaderIsNotASecondMechanism() {
        // §3.2.1 permits a client_id in the body for identification, so this must be accepted.
        ClientCredentialsCommand command = parser.parse(
                form("grant_type", "client_credentials", "client_id", "demo"),
                basicHeader("demo:secret"),
                false);

        assertThat(command.getPresentedMethod()).isEqualTo(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        assertThat(command.getClientSecret()).isEqualTo("secret");
    }

    @Test
    void rejectsABodySecretBesideABasicHeader() {
        // §2.3: a client must not use more than one authentication method.
        assertRejected(
                form("grant_type", "client_credentials", "client_secret", "secret"),
                basicHeader("demo:secret"),
                false);
    }

    @Test
    void rejectsCredentialsInTheQueryString() {
        // §2.3.1: credentials must not travel in the request URI.
        assertRejected(form("grant_type", "client_credentials"), null, true);
    }

    @Test
    void rejectsARepeatedParameter() {
        assertRejected(
                form("grant_type", "client_credentials", "grant_type", "client_credentials"),
                basicHeader("demo:secret"),
                false);
    }

    @Test
    void rejectsARepeatedScope() {
        assertRejected(
                form("grant_type", "client_credentials", "scope", "read", "scope", "write"),
                basicHeader("demo:secret"),
                false);
    }

    @Test
    void treatsAValuedParameterAsOmitted() {
        // §3.2: a parameter sent without a value is treated as if it were omitted.
        ClientCredentialsCommand command = parser.parse(
                form("grant_type", "client_credentials", "scope", ""),
                basicHeader("demo:secret"),
                false);

        assertThat(command.getScope()).isNull();
    }

    @Test
    void detectsCredentialsInTheQueryString() {
        assertThat(TokenRequestParser.credentialsInQueryString("client_id=demo")).isTrue();
        assertThat(TokenRequestParser.credentialsInQueryString("a=1&client_secret=x")).isTrue();
        assertThat(TokenRequestParser.credentialsInQueryString("scope=read")).isFalse();
        assertThat(TokenRequestParser.credentialsInQueryString(null)).isFalse();
        assertThat(TokenRequestParser.credentialsInQueryString("")).isFalse();
        // A parameter merely containing the name is not the parameter.
        assertThat(TokenRequestParser.credentialsInQueryString("my_client_id=x")).isFalse();
    }

    @Test
    void anUnparseableHeaderIsAnInvalidRequest() {
        assertThatThrownBy(() -> parser.parse(form("grant_type", "client_credentials"), "Basic !!!", false))
                .isInstanceOf(OAuth2Exception.class);
    }
}
