-- name: CreateUserAction :one
INSERT INTO user_actions (
    user_id,
    action
) VALUES (
    $1, $2
)
RETURNING *;