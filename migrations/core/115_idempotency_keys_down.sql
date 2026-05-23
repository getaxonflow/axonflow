-- Down migration 115: drop idempotency_keys table.

DROP TABLE IF EXISTS idempotency_keys;
