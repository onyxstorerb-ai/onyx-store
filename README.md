# ONYX STORE

Loja digital da ONYX para Cloudflare Workers + D1.

## Recursos
- Catálogo de produtos
- Carrinho/checkout
- Integração de cobrança LivePix
- Webhook de pagamento
- Reserva/baixa automática do estoque
- Entrega da conta somente após confirmação do pagamento
- Painel administrativo
- Estoque de contas
- Botão fixo para Discord
- Credenciais do estoque criptografadas antes de serem salvas no D1

## 1. Criar o D1

```bash
npx wrangler d1 create onyx-store-db
```

Copie o `database_id` retornado para `wrangler.jsonc`.

Depois:

```bash
npx wrangler d1 execute onyx-store-db --remote --file=./migrations/0001_init.sql
```

## 2. Secrets

No Cloudflare:

```bash
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put ENCRYPTION_KEY
npx wrangler secret put LIVEPIX_API_TOKEN
```

`ENCRYPTION_KEY` deve ser um segredo aleatório forte. Não coloque tokens ou senhas reais no GitHub.

## 3. LivePix

A aplicação usa a API LivePix CC para criar a cobrança e o webhook de pagamento.

Configure o webhook para:

`https://SEU-DOMINIO/api/livepix/webhook`

A URL de retorno é:

`https://SEU-DOMINIO/`

O código envia metadata com o ID do pedido.

## 4. Rodar

```bash
npm install
npm run dev
```

## 5. Deploy

```bash
npm run deploy
```

Se estiver usando GitHub + Cloudflare Workers Builds, conecte o repositório e deixe o build command como `npm run build`. O deploy é feito pelo Cloudflare Workers/Wrangler.

## Administração

Abra:

`/admin`

Use o valor definido em `ADMIN_PASSWORD`.

## Observação

O valor enviado à LivePix é o preço final cobrado do cliente. A taxa do gateway é responsabilidade da configuração/conta LivePix; o site não deve fingir uma taxa específica sem saber a taxa real da conta.
