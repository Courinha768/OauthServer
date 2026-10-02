package com.courinha.oauth2.core.adapter.out.persistence.file;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where the file-backed repositories keep their data.
 *
 * <p>Both paths are required, but only when {@code oauth2.persistence.repository=file}. The check
 * happens when a repository is constructed rather than at startup, so an in-memory deployment is
 * never asked for file paths it will not use.
 */
@Data
@ConfigurationProperties(prefix = "oauth2.file.persistence")
public class FileConfigs {

    /** Path to the clients JSON file. */
    private String clientsFilePath;

    /** Path to the access tokens JSON file. */
    private String accessTokensFilePath;
}
