-- V5: Add revoked column to api_keys table
ALTER TABLE api_keys ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;
