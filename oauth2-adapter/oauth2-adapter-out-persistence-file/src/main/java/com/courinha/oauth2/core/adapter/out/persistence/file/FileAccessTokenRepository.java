package com.courinha.oauth2.core.adapter.out.persistence.file;

import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.Scope;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import com.courinha.oauth2.core.domain.token.AccessToken;
import com.courinha.oauth2.core.domain.token.TokenType;
import tools.jackson.core.type.TypeReference;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A JSON-file-backed {@link AccessTokenRepository}, keyed by token value.
 *
 * <p>This is what makes an opaque token resolvable, and what will make revocation a delete for
 * both token formats.
 *
 * <p><strong>The file holds live credentials in the clear.</strong> An issued token is usable by
 * anyone who can read it, so the file needs the same care as a password store: restrictive
 * permissions, no backups to untrusted places, and no committing it to version control. A
 * production deployment should prefer a database with an encrypted volume. The file is created
 * owner-only where the platform supports POSIX permissions (see {@link JsonFileStore}), but that
 * is a default, not a guarantee about a file someone else created.
 */
public final class FileAccessTokenRepository implements AccessTokenRepository {

    private static final String TOKENS_PROPERTY = "access-tokens-file-path";
    private static final String WHAT = "access tokens";

    private static final TypeReference<List<AccessTokenRecord>> TOKENS_TYPE = new TypeReference<>() {
    };

    private final FileConfigs configs;
    private final ConcurrentMap<String, AccessToken> tokens = new ConcurrentHashMap<>();

    public FileAccessTokenRepository(FileConfigs configs) {
        this.configs = Objects.requireNonNull(configs, "configs");
        loadFromDisk();
    }

    @Override
    public synchronized void save(AccessToken token) {
        tokens.put(token.getValue(), token);
        persist();
    }

    public Optional<AccessToken> findByValue(String value) {
        return Optional.ofNullable(tokens.get(value));
    }

    public int size() {
        return tokens.size();
    }

    private Path filePath() {
        return JsonFileStore.resolve(configs.getAccessTokensFilePath(), TOKENS_PROPERTY);
    }

    private void loadFromDisk() {
        for (AccessTokenRecord record : JsonFileStore.read(filePath(), TOKENS_TYPE, WHAT)) {
            AccessToken token = toDomain(record);
            tokens.put(token.getValue(), token);
        }
    }

    private void persist() {
        JsonFileStore.write(filePath(), tokens.values().stream()
                .map(FileAccessTokenRepository::toRecord)
                .toList(), WHAT);
    }

    /** See {@link FileClientRepository} for why the enum is written as an explicit wire value. */
    private static AccessTokenRecord toRecord(AccessToken token) {
        return new AccessTokenRecord(
                token.getValue(),
                token.getClientId().getValue(),
                token.getScopes().getScopes().stream().map(Scope::getValue).toList(),
                token.getTokenType().getWireValue(),
                token.getIssuedAt().toString(),
                token.getExpiresAt().toString());
    }

    private static AccessToken toDomain(AccessTokenRecord record) {
        Objects.requireNonNull(record.value(), "record.value");
        Objects.requireNonNull(record.clientId(), "record.clientId");
        Objects.requireNonNull(record.scopes(), "record.scopes");
        Objects.requireNonNull(record.tokenType(), "record.tokenType");
        Objects.requireNonNull(record.issuedAt(), "record.issuedAt");
        Objects.requireNonNull(record.expiresAt(), "record.expiresAt");

        return AccessToken.builder()
                .value(record.value())
                .clientId(new ClientId(record.clientId()))
                .scopes(ScopeSet.of(record.scopes().toArray(String[]::new)))
                .tokenType(TokenType.fromWire(record.tokenType()).orElseThrow(() ->
                        new IllegalStateException(
                                "Unknown token type '%s' in the access tokens file"
                                        .formatted(record.tokenType()))))
                // Instants are stored as ISO-8601 text, which keeps the file readable and
                // independent of the JDK's default serialization choices.
                .issuedAt(Instant.parse(record.issuedAt()))
                .expiresAt(Instant.parse(record.expiresAt()))
                .build();
    }

    /** The on-disk shape. Kept separate from {@link AccessToken} so storage never shapes the model. */
    record AccessTokenRecord(String value,
                             String clientId,
                             List<String> scopes,
                             String tokenType,
                             String issuedAt,
                             String expiresAt) {
    }
}
