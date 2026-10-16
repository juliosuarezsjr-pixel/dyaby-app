# DYABY v15 — atualização integrada

Esta atualização parte do pacote v14 existente e mantém o projeto Node.js/Express/PostgreSQL, sem recriar a aplicação do zero.

## O que foi alterado
- A entrada e o cadastro mostram somente Cliente e Entregador.
- O backend recusa novos cadastros com perfil `commerce`; as tabelas e rotas internas existentes de comércio foram preservadas para não apagar dados antigos.
- Identidade visual escura com acentos neon, mantendo a estrutura anterior.
- Navegação por voz em português baseada nas etapas retornadas pelo OSRM e na localização GPS do navegador. A voz precisa ser iniciada manualmente, com permissão de localização e conexão ativa.
- Oferta de encomenda: após 2 minutos sem aceite, o cliente pode confirmar um aumento de R$ 2 ou R$ 5. O backend aplica um intervalo mínimo de 2 minutos entre aumentos e só permite alteração enquanto a entrega continua procurando entregador.
- Na tela do entregador, a entrega aceita apresenta total do cliente, comissão DYABY e valor líquido do entregador.
- Mantido o aviso de segurança para motoristas e o som de assinatura DYABY já existente.

## Instalação
1. Faça uma cópia de segurança do projeto e do banco de dados antes de substituir arquivos.
2. Extraia todos os arquivos deste ZIP para a pasta do projeto.
3. Preserve e configure as variáveis de ambiente já usadas pelo seu servidor (`DATABASE_URL`, `JWT_SECRET` e as demais integrações necessárias).
4. Execute `npm install` e depois `npm start`.

## O que precisa de teste real
- GPS e orientação por voz devem ser testados em celular, com permissão de localização, volume ativo e conexão de dados. A precisão e disponibilidade dependem do aparelho, do sinal e do serviço de rotas externo.
- A criação/aceitação de corridas e entregas, Pix, dinheiro e aprovação de motorista precisam ser testados com uma base de homologação antes de publicar.
- O aumento de oferta altera o total que o cliente paga; o cliente confirma cada aumento explicitamente.
- Não há garantia de disponibilidade dos serviços externos OpenStreetMap/OSRM.

## Importante
Este pacote não inclui credenciais, não executa deploy e não comprova que o banco remoto está acessível. Testes de sintaxe local não substituem testes integrados no ambiente de homologação.
