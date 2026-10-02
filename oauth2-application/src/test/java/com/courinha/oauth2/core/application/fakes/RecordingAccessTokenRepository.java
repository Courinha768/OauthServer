package com.courinha.oauth2.core.application.fakes;

import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.domain.token.AccessToken;

import java.util.ArrayList;
import java.util.List;

public final class RecordingAccessTokenRepository implements AccessTokenRepository {

    private final List<AccessToken> saved = new ArrayList<>();
    private boolean failOnSave;

    @Override
    public void save(AccessToken token) {
        if (failOnSave) {
            throw new IllegalStateException("token store unavailable");
        }
        saved.add(token);
    }

    public RecordingAccessTokenRepository failingOnSave() {
        this.failOnSave = true;
        return this;
    }

    public int saveCount() {
        return saved.size();
    }

    public AccessToken lastSaved() {
        if (saved.isEmpty()) {
            throw new IllegalStateException("Nothing has been saved");
        }
        return saved.get(saved.size() - 1);
    }

    public boolean hasSavedAnything() {
        return !saved.isEmpty();
    }
}
