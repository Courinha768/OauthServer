package com.courinha.oauth2.core.adapter.out.persistence.file;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * The file half of the two repositories: locating the data file, reading a JSON array from it,
 * and writing one back.
 *
 * <p>Shared rather than duplicated so that the awkward parts — path validation, the
 * missing-file case, restrictive permissions — exist in exactly one place. The repositories keep
 * only the mapping between their records and the domain.
 */
final class JsonFileStore {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Owner read and write only. Applied when a data file is created for the first time. */
    private static final String OWNER_ONLY = "rw-------";

    private JsonFileStore() {
    }

    /**
     * Validates and resolves a configured path.
     *
     * <p>The check happens here rather than through bean validation at startup, so that an
     * in-memory deployment is never asked for file paths it will not use.
     */
    static Path resolve(String rawPath, String propertyName) {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalStateException(
                    "Property oauth2.file.persistence.%s must be set when oauth2.persistence.repository=file"
                            .formatted(propertyName));
        }
        return Path.of(rawPath);
    }

    /**
     * Reads a JSON array. A missing file reads as an empty list, which is what a first run looks
     * like; a file that exists but cannot be understood is an error, because treating it as empty
     * would silently discard every stored record.
     */
    static <T> List<T> read(Path filePath, TypeReference<List<T>> type, String what) {
        if (!Files.exists(filePath)) {
            return List.of();
        }
        try {
            List<T> records = MAPPER.readValue(filePath.toFile(), type);
            return records == null ? List.of() : records;
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "Failed to read %s from JSON file '%s'".formatted(what, filePath), e);
        }
    }

    static <T> void write(Path filePath, List<T> records, String what) {
        try {
            Path parent = filePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            createOwnerOnlyIfAbsent(filePath);
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(filePath.toFile(), records);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to write %s to JSON file '%s'".formatted(what, filePath), e);
        }
    }

    /**
     * Creates the file with owner-only permissions the first time it is written.
     *
     * <p>These files hold client hashes and live access tokens, so the safe default matters more
     * than the convenient one; on a shared host a world-readable token file hands out working
     * credentials. An existing file is left exactly as the operator set it up, because a
     * deployment may have a deliberate reason for wider access and re-applying this on every
     * write would quietly undo it.
     *
     * <p>POSIX permissions do not exist on Windows, where this is a no-op.
     */
    private static void createOwnerOnlyIfAbsent(Path filePath) throws IOException {
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        try {
            Files.createFile(filePath, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString(OWNER_ONLY)));
        } catch (FileAlreadyExistsException alreadyThere) {
            // Deliberately leave the existing file's permissions alone.
        }
    }
}
