-- +goose Up

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE user_action_type AS ENUM ('user_register', 'user_login');

CREATE TABLE IF NOT EXISTS user_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action user_action_type NOT NULL
);

-- +goose Down

DROP TABLE IF EXISTS user_actions;

DROP TYPE IF EXISTS user_action_type;