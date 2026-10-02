package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.application.port.in.ClientCredentialsCommand;
import com.courinha.oauth2.core.application.port.in.IssueClientCredentialsTokenUseCase;
import com.courinha.oauth2.core.domain.token.AccessToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

/**
 * The RFC 6749 §3.2 token endpoint.
 *
 * <p>The controller is deliberately thin: it binds the request, delegates to the inbound port,
 * and renders the result. No protocol decision is made here.
 *
 * <p>Parameters bind as a {@link MultiValueMap} rather than individual {@code @RequestParam}
 * values because Spring silently collapses repeated parameters otherwise, and §3.2 forbids any
 * parameter appearing more than once.
 *
 * <p>No {@code consumes} restriction is declared. A request with a non-form content type simply
 * yields no parameters, and the missing {@code grant_type} becomes an {@code invalid_request} —
 * which is the §5.2 response we want, rather than Spring's own 415.
 */
@RestController
public class TokenEndpointController {

    private final IssueClientCredentialsTokenUseCase useCase;
    private final TokenRequestParser requestParser;

    public TokenEndpointController(IssueClientCredentialsTokenUseCase useCase, TokenRequestParser requestParser) {
        this.useCase = Objects.requireNonNull(useCase);
        this.requestParser = Objects.requireNonNull(requestParser);
    }

    @PostMapping("/oauth2/token")
    public ResponseEntity<TokenResponseBody> issueToken(
            @RequestParam MultiValueMap<String, String> parameters,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            HttpServletRequest request) {

        ClientCredentialsCommand command = requestParser.parse(
                parameters,
                authorization,
                TokenRequestParser.credentialsInQueryString(request.getQueryString()));

        AccessToken token = useCase.issue(command);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(TokenResponseBody.from(token));
    }
}
