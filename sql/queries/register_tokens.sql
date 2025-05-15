-- name: CreateToken :one
INSERT INTO register_tokens (username)
VALUES ($1)
RETURNING *;

-- name: GetTokenByID :one
SELECT * FROM register_tokens
WHERE id = $1;

-- name: SetTokenUsed :exec
UPDATE register_tokens
SET used = true,
    updated_at = now()
WHERE id = $1;