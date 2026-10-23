CREATE TABLE users (
    id                   UUID PRIMARY KEY,
    email                VARCHAR(254) NOT NULL,
    auth_hash            VARCHAR(255) NOT NULL,
    kdf_salt             VARCHAR(64)  NOT NULL,
    kdf_iterations       INTEGER      NOT NULL CHECK (kdf_iterations >= 600000),
    protected_vault_key  VARCHAR(256) NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL,
    updated_at           TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT ck_users_email_normalized CHECK (email = lower(btrim(email)))
);

CREATE TABLE credentials (
    id                   UUID PRIMARY KEY,
    user_id              UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    encrypted_name       TEXT         NOT NULL,
    encrypted_url        TEXT,
    encrypted_username   TEXT,
    encrypted_password   TEXT         NOT NULL,
    encrypted_notes      TEXT,
    favorite             BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ  NOT NULL,
    updated_at           TIMESTAMPTZ  NOT NULL,
    password_updated_at  TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_credentials_user_updated ON credentials (user_id, updated_at DESC);
CREATE INDEX idx_credentials_user_favorite ON credentials (user_id) WHERE favorite;
