package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.application.port.in.ClientCredentialsCommand;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import org.springframework.util.MultiValueMap;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Turns a token request's HTTP shape into a {@link ClientCredentialsCommand}.
 *
 * <p>Everything here is about <em>form</em> rather than protocol meaning: which parameters
 * appeared, how often, and through which mechanism credentials arrived. Deciding what a problem
 * means is the use case's job, which is why this class only ever raises {@code invalid_request}.
 */
public final class TokenRequestParser {

    private static final String PARAM_GRANT_TYPE = "grant_type";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_CLIENT_SECRET = "client_secret";

    private final BasicAuthHeaderParser basicAuthHeaderParser;

    public TokenRequestParser(BasicAuthHeaderParser basicAuthHeaderParser) {
        this.basicAuthHeaderParser = Objects.requireNonNull(basicAuthHeaderParser);
    }

    /**
     * @param form                  the request parameters, taken as a {@link MultiValueMap} so
     *                              that repeats are visible
     * @param authorizationHeader   the raw {@code Authorization} header, or {@code null}
     * @param credentialsInQuery    whether {@code client_id} or {@code client_secret} appeared
     *                              in the request URI
     */
    public ClientCredentialsCommand parse(
            MultiValueMap<String, String> form,
            String authorizationHeader,
            boolean credentialsInQuery) {

        rejectRepeatedParameters(form);

        if (credentialsInQuery) {
            // §2.3.1: credentials must not travel in the request URI.
            throw OAuth2Exception.invalidRequest(
                    "Client credentials must not be sent in the request URI");
        }

        String grantType = singleValue(form, PARAM_GRANT_TYPE);
        String scope = singleValue(form, PARAM_SCOPE);
        String bodyClientId = singleValue(form, PARAM_CLIENT_ID);
        String bodyClientSecret = singleValue(form, PARAM_CLIENT_SECRET);

        Optional<BasicCredentials> basic = basicAuthHeaderParser.parse(authorizationHeader);

        if (basic.isPresent() && bodyClientSecret != null) {
            // §2.3: one method per request. A bare client_id beside a Basic header is not a
            // second mechanism — §3.2.1 allows it for identification — but a body secret is.
            throw OAuth2Exception.invalidRequest(
                    "Client must not use more than one authentication method");
        }

        if (basic.isPresent()) {
            BasicCredentials credentials = basic.get();
            return ClientCredentialsCommand.builder()
                    .clientId(credentials.getClientId())
                    .clientSecret(credentials.getClientSecret())
                    .presentedMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                    .grantType(grantType)
                    .scope(scope)
                    .build();
        }

        if (bodyClientId != null || bodyClientSecret != null) {
            return ClientCredentialsCommand.builder()
                    .clientId(bodyClientId)
                    .clientSecret(bodyClientSecret)
                    .presentedMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                    .grantType(grantType)
                    .scope(scope)
                    .build();
        }

        return ClientCredentialsCommand.builder()
                .presentedMethod(TokenEndpointAuthMethod.NONE)
                .grantType(grantType)
                .scope(scope)
                .build();
    }

    /**
     * RFC 6749 §3.2: a parameter must not appear more than once.
     *
     * <p>Spring collapses repeated form parameters when binding to a plain {@code String} or
     * {@code Map}, which would hide the violation entirely — hence the {@link MultiValueMap}.
     */
    private static void rejectRepeatedParameters(MultiValueMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry : form.entrySet()) {
            if (entry.getValue().size() > 1) {
                throw OAuth2Exception.duplicateParameter(entry.getKey());
            }
        }
    }

    /**
     * RFC 6749 §3.2: a parameter sent without a value is treated as if it were omitted, so an
     * empty value becomes {@code null} here and every later check sees it as absent.
     */
    private static String singleValue(MultiValueMap<String, String> form, String name) {
        String value = form.getFirst(name);
        return (value == null || value.isEmpty()) ? null : value;
    }

    /**
     * Whether the request URI carries client credentials, which §2.3.1 forbids.
     *
     * <p>Parsed from the raw query string rather than from the bound parameters, because Spring
     * merges query and form parameters and the distinction would otherwise be lost.
     */
    public static boolean credentialsInQueryString(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return false;
        }
        for (String pair : queryString.split("&")) {
            int equals = pair.indexOf('=');
            String name = equals < 0 ? pair : pair.substring(0, equals);
            String decoded;
            try {
                decoded = URLDecoder.decode(name, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                decoded = name;
            }
            if (PARAM_CLIENT_ID.equals(decoded) || PARAM_CLIENT_SECRET.equals(decoded)) {
                return true;
            }
        }
        return false;
    }
}
