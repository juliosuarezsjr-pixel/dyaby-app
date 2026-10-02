# DYABY — banco persistente PostgreSQL

Esta atualização troca o SQLite local pelo PostgreSQL do Render para evitar que os cadastros desapareçam após redeploy/restart.

## Arquivos
- `server.js` — backend com PostgreSQL
- `package.json` — dependências atualizadas

## Render
1. Crie/conecte um PostgreSQL ao serviço `dyaby-app`.
2. Em Environment, adicione `DATABASE_URL` usando a Internal Database URL do PostgreSQL.
3. Mantenha `JWT_SECRET`, `ADMIN_EMAIL` e `ADMIN_PASSWORD` configurados com valores fortes.
4. Faça deploy pelo GitHub.
5. Abra `/api/health`. Deve retornar `"database":"postgresql"`.

## Importante
A base PostgreSQL começa vazia. Os usuários que existiam somente no SQLite antigo não são copiados automaticamente. Depois de configurar o PostgreSQL, faça um novo cadastro de teste e confirme que ele continua funcionando após um novo deploy/restart.

Os uploads ainda ficam no filesystem local; para documentos de motorista em produção, use armazenamento persistente/objeto (ex.: S3/R2/Supabase Storage) em uma etapa posterior.
