package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2Error;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The RFC 6749 §5.2 error response body. {@code error} is always present; the other two members
 * are omitted when absent.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponseBody {

    @JsonProperty("error")
    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    @JsonProperty("error_uri")
    private String errorUri;

    public static ErrorResponseBody from(OAuth2Error source) {
        return ErrorResponseBody.builder()
                .error(source.getCode().getWireValue())
                .errorDescription(source.getDescription())
                .errorUri(source.getErrorUri())
                .build();
    }
}
