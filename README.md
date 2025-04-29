SQL script for DB:
```sql
CREATE DATABASE auth_db;
\c auth_db

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    access_token_id TEXT NOT NULL,
    ip_address TEXT NOT NULL
);
```
