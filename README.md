# DYABY — atualização de cancelamento

Esta versão adiciona a regra de compensação de cancelamento ao fluxo real de corridas.

## Regra
- O relógio começa quando o motorista inicia a corrida (`started`).
- Se o passageiro cancelar antes de 3 minutos: sem compensação automática.
- Se cancelar a partir de 3 minutos: R$ 5,00 de compensação registrada para o motorista.
- Cancelamentos por emergência, acidente ou segurança não recebem compensação automática e podem ser analisados.
- A compensação é gravada na corrida no campo `driver_compensation` e aparece para passageiro e motorista.

## Deploy
Substitua os arquivos `server.js`, `index.html` e `package.json` no repositório conectado ao Render e faça um novo deploy.

> Observação: esta versão ainda usa SQLite local. Para produção no Render, migrar para PostgreSQL antes de considerar os dados permanentes.
