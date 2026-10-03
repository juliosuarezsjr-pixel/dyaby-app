# DYABY — correção PostgreSQL

Esta versão mantém o backend do cadastro e troca o banco principal de SQLite para PostgreSQL usando `DATABASE_URL`.

No Render, configure:
- DATABASE_URL
- ADMIN_EMAIL
- ADMIN_PASSWORD
- JWT_SECRET

A `DATABASE_URL` deve ser a Internal Database URL do PostgreSQL `dyaby-db`.
