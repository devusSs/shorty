-- +goose Up

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS register_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    username TEXT NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT false 
);

-- +goose Down

DROP TABLE IF EXISTS register_tokens;