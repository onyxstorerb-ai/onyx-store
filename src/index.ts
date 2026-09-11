export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

  ADMIN_PASSWORD: string;
  ENCRYPTION_KEY: string;

  // Mantido para compatibilidade.
  LIVEPIX_API_TOKEN: string;

  LIVEPIX_CLIENT_ID: string;
  LIVEPIX_CLIENT_SECRET: string;

  // Link do servidor Discord.
  DISCORD_URL?: string;

  SITE_URL?: string;
}

const LIVEPIX_OAUTH_URL =
  "https://oauth.livepix.gg/oauth2/token";

const LIVEPIX_API_URL =
  "https://api.livepix.gg/v2";

const LIVEPIX_FEE_PERCENT = 5;

const DEFAULT_DISCORD_URL =
  "https://discord.gg/p9ZmkncQ8q";

let oauthCache: {
  accessToken: string;
  expiresAt: number;
} | null = null;

const json = (
  data: unknown,
  status = 200
) =>
  new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=utf-8",
        "cache-control":
          "no-store"
      }
    }
  );

function id(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

function adminAuthorized(
  request: Request,
  env: Env
) {
  return (
    request.headers.get(
      "x-admin-password"
    ) === env.ADMIN_PASSWORD
  );
}

/* =========================================================
   CRIPTOGRAFIA
========================================================= */

async function keyFromSecret(
  secret: string
) {
  const bytes =
    new TextEncoder().encode(secret);

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      bytes
    );

  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    [
      "encrypt",
      "decrypt"
    ]
  );
}

async function encrypt(
  text: string,
  secret: string
) {
  const key =
    await keyFromSecret(secret);

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      new TextEncoder().encode(text)
    );

  const result =
    new Uint8Array(
      iv.length +
      encrypted.byteLength
    );

  result.set(iv, 0);

  result.set(
    new Uint8Array(encrypted),
    iv.length
  );

  return btoa(
    String.fromCharCode(...result)
  );
}

async function decrypt(
  value: string,
  secret: string
) {
  const raw =
    Uint8Array.from(
      atob(value),
      c => c.charCodeAt(0)
    );

  const iv =
    raw.slice(0, 12);

  const data =
    raw.slice(12);

  const key =
    await keyFromSecret(secret);

  const decrypted =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      data
    );

  return new TextDecoder()
    .decode(decrypted);
}

/* =========================================================
   PAGAMENTO
========================================================= */

function amountWithFee(
  amountCents: number
) {
  const fee =
    LIVEPIX_FEE_PERCENT / 100;

  if (
    !Number.isFinite(
      amountCents
    ) ||
    amountCents <= 0
  ) {
    throw new Error(
      "Valor inválido."
    );
  }

  return Math.ceil(
    amountCents /
    (1 - fee)
  );
}

/* =========================================================
   LIVEPIX OAUTH
========================================================= */

async function getLivepixAccessToken(
  env: Env
) {
  if (
    !env.LIVEPIX_CLIENT_ID ||
    !env.LIVEPIX_CLIENT_SECRET
  ) {
    throw new Error(
      "Credenciais OAuth2 do LivePix não configuradas."
    );
  }

  const now =
    Date.now();

  if (
    oauthCache &&
    oauthCache.expiresAt >
      now + 60_000
  ) {
    return oauthCache.accessToken;
  }

  const body =
    new URLSearchParams({
      grant_type:
        "client_credentials",

      client_id:
        env.LIVEPIX_CLIENT_ID,

      client_secret:
        env.LIVEPIX_CLIENT_SECRET,

      scope:
        "payments:read payments:write"
    });

  const response =
    await fetch(
      LIVEPIX_OAUTH_URL,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  const raw =
    await response.text();

  let data: any = {};

  try {
    data =
      JSON.parse(raw);
  } catch {
    data = {};
  }

  if (
    !response.ok ||
    !data?.access_token
  ) {
    throw new Error(
      data?.error_description ||
      data?.message ||
      `Falha OAuth2 LivePix (${response.status}).`
    );
  }

  oauthCache = {
    accessToken:
      data.access_token,

    expiresAt:
      now +
      Number(
        data.expires_in || 3600
      ) *
      1000
  };

  return data.access_token;
}

/* =========================================================
   LIVEPIX REQUEST
========================================================= */

async function livepixRequest(
  env: Env,
  path: string,
  init: RequestInit = {}
) {
  const accessToken =
    await getLivepixAccessToken(
      env
    );

  const headers =
    new Headers(
      init.headers
    );

  headers.set(
    "Authorization",
    `Bearer ${accessToken}`
  );

  headers.set(
    "Accept",
    "application/json"
  );

  if (
    init.body &&
    !headers.has(
      "Content-Type"
    )
  ) {
    headers.set(
      "Content-Type",
      "application/json"
    );
  }

  let response =
    await fetch(
      `${LIVEPIX_API_URL}${path}`,
      {
        ...init,
        headers
      }
    );

  if (
    response.status === 401
  ) {
    oauthCache = null;

    const retryToken =
      await getLivepixAccessToken(
        env
      );

    headers.set(
      "Authorization",
      `Bearer ${retryToken}`
    );

    response =
      await fetch(
        `${LIVEPIX_API_URL}${path}`,
        {
          ...init,
          headers
        }
      );
  }

  return response;
}

/* =========================================================
   CRIAR PAGAMENTO
========================================================= */

async function livepixCreatePayment(
  env: Env,
  amountCents: number,
  description: string,
  orderId: string,
  origin: string
) {
  const chargedAmountCents =
    amountWithFee(
      amountCents
    );

  const redirectUrl =
    `${origin}/?paid=${encodeURIComponent(
      orderId
    )}`;

  const response =
    await livepixRequest(
      env,
      "/payments",
      {
        method: "POST",

        body: JSON.stringify({
          amount:
            chargedAmountCents,

          currency:
            "BRL",

          redirectUrl
        })
      }
    );

  const raw =
    await response.text();

  let body: any = {};

  try {
    body =
      JSON.parse(raw);
  } catch {
    body = {};
  }

  if (!response.ok) {
    throw new Error(
      body?.message ||
      body?.error_description ||
      body?.error ||
      `Falha ao criar pagamento LivePix (${response.status}).`
    );
  }

  const payment =
    body?.data;

  if (
    !payment?.reference ||
    !payment?.redirectUrl
  ) {
    throw new Error(
      "Resposta inválida do LivePix."
    );
  }

  return {
    ...payment,

    description,

    chargedAmountCents,

    orderId
  };
}

/* =========================================================
   BUSCAR PAGAMENTO
========================================================= */

async function verifyLivepixPayment(
  env: Env,
  paymentId: string
) {
  if (!paymentId) {
    return null;
  }

  const response =
    await livepixRequest(
      env,
      `/payments/${encodeURIComponent(
        paymentId
      )}`
    );

  if (!response.ok) {
    return null;
  }

  const body =
    await response.json<any>();

  return (
    body?.data ??
    null
  );
}

async function findLivepixPaymentByReference(
  env: Env,
  reference: string
) {
  if (!reference) {
    return null;
  }

  const query =
    new URLSearchParams({
      reference
    });

  const response =
    await livepixRequest(
      env,
      `/payments?${query.toString()}`
    );

  if (!response.ok) {
    return null;
  }

  const body =
    await response.json<any>();

  const payments =
    Array.isArray(
      body?.data
    )
      ? body.data
      : [];

  return (
    payments.find(
      (payment: any) =>
        String(
          payment?.reference ||
          ""
        ) === reference
    ) ??
    payments[0] ??
    null
  );
}

/* =========================================================
   ESTOQUE
========================================================= */

/*
 * O estoque NÃO é reservado no checkout.
 *
 * Uma conta só passa de available -> sold
 * depois que o pagamento foi confirmado.
 *
 * A operação usa o próprio pedido como condição
 * para impedir que dois webhooks confirmem
 * o mesmo pedido simultaneamente.
 */
async function claimInventoryForPaidOrder(
  env: Env,
  orderId: string,
  productId: string,
  paymentId: string,
  reference: string
) {
  const result =
    await env.DB.batch([
      /*
       * 1. Pega uma única conta disponível.
       *
       * Só pode fazer isso se o pedido ainda
       * estiver pending.
       */
      env.DB.prepare(
        `UPDATE inventory
         SET
           status='sold',
           order_id=?,
           sold_at=CURRENT_TIMESTAMP
         WHERE id = (
           SELECT i.id
           FROM inventory i
           JOIN orders o
             ON o.id=?
           WHERE i.product_id=?
             AND i.status='available'
             AND o.status='pending'
           ORDER BY i.created_at ASC
           LIMIT 1
         )
         AND status='available'`
      ).bind(
        orderId,
        orderId,
        productId
      ),

      /*
       * 2. Marca o pedido como pago
       * somente se uma conta foi atribuída.
       */
      env.DB.prepare(
        `UPDATE orders
         SET
           status='paid',
           inventory_id=(
             SELECT id
             FROM inventory
             WHERE order_id=?
               AND status='sold'
             LIMIT 1
           ),
           livepix_id=?,
           livepix_reference=?,
           paid_at=CURRENT_TIMESTAMP
         WHERE id=?
           AND status='pending'
           AND EXISTS (
             SELECT 1
             FROM inventory
             WHERE order_id=?
               AND status='sold'
           )`
      ).bind(
        orderId,
        paymentId,
        reference,
        orderId,
        orderId
      ),

      /*
       * 3. Recupera a conta atribuída.
       */
      env.DB.prepare(
        `SELECT
           i.id,
           i.product_id,
           i.account_encrypted,
           i.status,
           i.order_id
         FROM inventory i
         WHERE i.order_id=?
           AND i.status='sold'
         LIMIT 1`
      ).bind(
        orderId
      ),

      /*
       * 4. Recupera o estado final do pedido.
       */
      env.DB.prepare(
        `SELECT
           id,
           status,
           inventory_id
         FROM orders
         WHERE id=?
         LIMIT 1`
      ).bind(
        orderId
      )
    ]);

  const inventory =
    result[2]
      ?.results?.[0] as any;

  const finalOrder =
    result[3]
      ?.results?.[0] as any;

  /*
   * Se o pedido já tinha sido pago,
   * não entrega uma segunda conta.
   */
  if (
    finalOrder?.status ===
      "paid" &&
    !inventory
  ) {
    return {
      ok: true,
      alreadyPaid: true,
      orderId
    };
  }

  /*
   * Se não conseguiu pegar estoque,
   * o pedido continua sem consumo.
   */
  if (!inventory) {
    return {
      ok: false,
      reason:
        "out_of_stock_after_payment"
    };
  }

  /*
   * Confirma que o pedido realmente
   * terminou como paid.
   */
  if (
    finalOrder?.status !==
    "paid"
  ) {
    return {
      ok: false,
      reason:
        "order_not_paid"
    };
  }

  return {
    ok: true,
    alreadyPaid: false,
    inventory,
    orderId
  };
}

/* =========================================================
   APROVAR PAGAMENTO + ENTREGAR
========================================================= */

async function markPaidAndDeliver(
  env: Env,
  payment: any
) {
  const paymentId =
    String(
      payment?.id ||
      ""
    );

  const reference =
    String(
      payment?.reference ||
      ""
    );

  if (
    !paymentId &&
    !reference
  ) {
    return {
      ok: false,
      reason:
        "missing_payment_identifier"
    };
  }

  /*
   * Localiza o pedido.
   */
  let order =
    reference
      ? await env.DB.prepare(
          `SELECT *
           FROM orders
           WHERE livepix_reference=?
           LIMIT 1`
        )
          .bind(
            reference
          )
          .first<any>()
      : null;

  if (
    !order &&
    paymentId
  ) {
    order =
      await env.DB.prepare(
        `SELECT *
         FROM orders
         WHERE livepix_id=?
         LIMIT 1`
      )
        .bind(
          paymentId
        )
        .first<any>();
  }

  if (!order) {
    return {
      ok: false,
      reason:
        "order_not_found"
    };
  }

  /*
   * Idempotência:
   *
   * Se o pedido já está pago,
   * nunca tenta pegar outra conta.
   */
  if (
    order.status ===
    "paid"
  ) {
    return {
      ok: true,
      alreadyPaid: true,
      orderId:
        order.id
    };
  }

  /*
   * Confirma diretamente no LivePix.
   */
  let verified: any = null;

  if (paymentId) {
    verified =
      await verifyLivepixPayment(
        env,
        paymentId
      );
  }

  if (
    !verified &&
    reference
  ) {
    verified =
      await findLivepixPaymentByReference(
        env,
        reference
      );
  }

  if (!verified) {
    return {
      ok: false,
      reason:
        "payment_not_found"
    };
  }

  /*
   * Só aprova se o LivePix fornecer
   * a prova de pagamento.
   */
  if (
    !verified.proof
  ) {
    return {
      ok: false,
      reason:
        "payment_not_verified"
    };
  }

  /*
   * Confere moeda.
   */
  if (
    String(
      verified.currency ||
      ""
    ).toUpperCase() !==
    "BRL"
  ) {
    return {
      ok: false,
      reason:
        "invalid_currency"
    };
  }

  /*
   * Confere valor.
   */
  const livepixAmount =
    Number(
      verified.amount
    );

  const orderAmount =
    Number(
      order.amount_cents
    );

  if (
    !Number.isFinite(
      livepixAmount
    ) ||
    livepixAmount !==
      orderAmount
  ) {
    return {
      ok: false,
      reason:
        "amount_mismatch"
    };
  }

  const finalPaymentId =
    String(
      verified.id ||
      paymentId ||
      ""
    );

  const finalReference =
    String(
      verified.reference ||
      reference ||
      ""
    );

  /*
   * Só agora o estoque é consumido.
   *
   * Se não houver conta disponível,
   * nenhuma conta é removida.
   */
  const claimed =
    await claimInventoryForPaidOrder(
      env,
      order.id,
      order.product_id,
      finalPaymentId,
      finalReference
    );

  if (!claimed.ok) {
    return claimed;
  }

  /*
   * Webhook repetido.
   */
  if (
    claimed.alreadyPaid
  ) {
    return {
      ok: true,
      alreadyPaid: true,
      orderId:
        order.id
    };
  }

  const inventory =
    claimed.inventory;

  /*
   * Descriptografa somente depois
   * da confirmação do pagamento.
   */
  const account =
    await decrypt(
      inventory.account_encrypted,
      env.ENCRYPTION_KEY
    );

  return {
    ok: true,

    alreadyPaid: false,

    account,

    orderId:
      order.id,

    product:
      order.product_id
  };
}

/* =========================================================
   WEBHOOK LIVEPIX
========================================================= */

async function handleLivepixWebhook(
  request: Request,
  env: Env
) {
  let payload: any;

  try {
    payload =
      await request.json<any>();
  } catch {
    return json(
      {
        error:
          "JSON inválido."
      },
      400
    );
  }

  /*
   * Confere clientId quando enviado.
   */
  if (
    payload?.clientId &&
    String(
      payload.clientId
    ) !==
      String(
        env.LIVEPIX_CLIENT_ID
      )
  ) {
    return json(
      {
        error:
          "Cliente LivePix inválido."
      },
      401
    );
  }

  /*
   * Eventos diferentes de "new"
   * não precisam alterar o pedido.
   */
  if (
    payload?.event &&
    payload.event !==
      "new"
  ) {
    return json({
      status:
        "ignored"
    });
  }

  const resource =
    payload?.resource ??
    payload?.data ??
    payload;

  const paymentId =
    String(
      resource?.id ||
      ""
    );

  const reference =
    String(
      resource?.reference ||
      ""
    );

  if (
    !paymentId &&
    !reference
  ) {
    return json(
      {
        error:
          "Pagamento sem identificador."
      },
      400
    );
  }

  let payment: any = null;

  if (paymentId) {
    payment =
      await verifyLivepixPayment(
        env,
        paymentId
      );
  }

  if (
    !payment &&
    reference
  ) {
    payment =
      await findLivepixPaymentByReference(
        env,
        reference
      );
  }

  if (!payment) {
    return json({
      status:
        "payment_not_found"
    });
  }

  const result =
    await markPaidAndDeliver(
      env,
      payment
    );

  if (result.ok) {
    return json({
      status:
        "ok",

      orderId:
        result.orderId ??
        null,

      alreadyPaid:
        result.alreadyPaid ??
        false
    });
  }

  if (
    result.reason ===
    "order_not_found"
  ) {
    return json(
      result,
      404
    );
  }

  /*
   * Pagamento confirmado mas sem estoque.
   *
   * Não inventa entrega e não pega
   * outra conta.
   */
  if (
    result.reason ===
    "out_of_stock_after_payment"
  ) {
    console.error(
      "Pagamento confirmado sem estoque:",
      result
    );

    return json(
      {
        ...result,
        status:
          "payment_confirmed_no_stock"
      },
      409
    );
  }

  return json(
    result,
    400
  );
}

/* =========================================================
   API
========================================================= */

async function api(
  request: Request,
  env: Env,
  url: URL
) {
  const path =
    url.pathname;

  /* =======================================================
     PRODUTOS
  ======================================================= */

  if (
    request.method === "GET" &&
    path ===
      "/api/products"
  ) {
    const products =
      await env.DB.prepare(
        `SELECT
          p.id,
          p.name,
          p.description,
          p.price_cents,

          (
            SELECT COUNT(*)
            FROM inventory i
            WHERE i.product_id=p.id
              AND i.status='available'
          ) AS stock

         FROM products p

         WHERE p.active=1

         ORDER BY
           p.created_at DESC`
      ).all();

    return json(
      products.results
    );
  }

  /* =======================================================
     CHECKOUT
  ======================================================= */

  if (
    request.method === "POST" &&
    path ===
      "/api/checkout"
  ) {
    let body: any;

    try {
      body =
        await request.json<any>();
    } catch {
      return json(
        {
          error:
            "JSON inválido."
        },
        400
      );
    }

    const productId =
      String(
        body?.productId ||
        ""
      );

    if (!productId) {
      return json(
        {
          error:
            "Produto não informado."
        },
        400
      );
    }

    const product =
      await env.DB.prepare(
        `SELECT *
         FROM products
         WHERE id=?
           AND active=1
         LIMIT 1`
      )
        .bind(
          productId
        )
        .first<any>();

    if (!product) {
      return json(
        {
          error:
            "Produto não encontrado."
        },
        404
      );
    }

    const baseAmountCents =
      Number(
        product.price_cents
      );

    if (
      !Number.isFinite(
        baseAmountCents
      ) ||
      baseAmountCents <= 0
    ) {
      return json(
        {
          error:
            "Preço inválido."
        },
        500
      );
    }

    /*
     * Apenas verifica se existe estoque.
     *
     * NÃO reserva nenhuma conta.
     */
    const stock =
      await env.DB.prepare(
        `SELECT COUNT(*) AS total
         FROM inventory
         WHERE product_id=?
           AND status='available'`
      )
        .bind(
          product.id
        )
        .first<any>();

    const availableStock =
      Number(
        stock?.total || 0
      );

    if (
      availableStock <= 0
    ) {
      return json(
        {
          error:
            "Produto sem estoque."
        },
        409
      );
    }

    const orderId =
      id("ord");

    const chargedAmountCents =
      amountWithFee(
        baseAmountCents
      );

    /*
     * Cria o pedido como pending.
     *
     * inventory_id fica NULL.
     *
     * Portanto:
     * pending != estoque consumido.
     */
    try {
      await env.DB.prepare(
        `INSERT INTO orders
         (
           id,
           product_id,
           inventory_id,
           amount_cents,
           status
         )
         VALUES
         (?, ?, NULL, ?, 'pending')`
      )
        .bind(
          orderId,
          product.id,
          chargedAmountCents
        )
        .run();
    } catch (error) {
      console.error(
        "Erro ao criar pedido:",
        error
      );

      return json(
        {
          error:
            "Não foi possível criar o pedido."
        },
        500
      );
    }

    /*
     * Cria cobrança LivePix.
     */
    try {
      const payment =
        await livepixCreatePayment(
          env,
          baseAmountCents,
          `ONYX - ${product.name}`,
          orderId,
          url.origin
        );

      await env.DB.prepare(
        `UPDATE orders
         SET
           livepix_id=?,
           livepix_reference=?
         WHERE id=?`
      )
        .bind(
          payment.id ??
            null,

          payment.reference,

          orderId
        )
        .run();

      return json(
        {
          orderId,

          checkout:
            payment.redirectUrl,

          pixCode:
            null,

          pixQrCode:
            null,

          expiresAt:
            null,

          amountCents:
            chargedAmountCents,

          baseAmountCents:
            baseAmountCents,

          feePercent:
            LIVEPIX_FEE_PERCENT
        },
        201
      );
    } catch (error) {
      /*
       * Como nenhuma conta foi reservada,
       * aqui só precisamos cancelar o pedido.
       */
      await env.DB.prepare(
        `UPDATE orders
         SET status='cancelled'
         WHERE id=?
           AND status='pending'`
      )
        .bind(
          orderId
        )
        .run();

      console.error(
        "LivePix checkout error:",
        error
      );

      return json(
        {
          error:
            error instanceof Error
              ? error.message
              : "Erro no pagamento."
        },
        502
      );
    }
  }

  /* =======================================================
     PEDIDO / ENTREGA
  ======================================================= */

  if (
    request.method === "GET" &&
    path.startsWith(
      "/api/order/"
    )
  ) {
    const orderId =
      decodeURIComponent(
        path.slice(
          "/api/order/".length
        )
      );

    if (!orderId) {
      return json(
        {
          error:
            "Pedido inválido."
        },
        400
      );
    }

    const order =
      await env.DB.prepare(
        `SELECT
          o.id,
          o.status,
          o.amount_cents,
          p.name
         FROM orders o
         JOIN products p
           ON p.id=o.product_id
         WHERE o.id=?
         LIMIT 1`
      )
        .bind(
          orderId
        )
        .first<any>();

    if (!order) {
      return json(
        {
          error:
            "Pedido não encontrado."
        },
        404
      );
    }

    /*
     * Enquanto não estiver pago,
     * NÃO entrega a conta.
     */
    if (
      order.status !==
      "paid"
    ) {
      return json({
        id:
          order.id,

        status:
          order.status,

        product:
          order.name,

        amountCents:
          order.amount_cents,

        delivered:
          false
      });
    }

    /*
     * Depois do pagamento,
     * encontra a conta pelo order_id.
     */
    const inventory =
      await env.DB.prepare(
        `SELECT
          account_encrypted
         FROM inventory
         WHERE order_id=?
           AND status='sold'
         LIMIT 1`
      )
        .bind(
          order.id
        )
        .first<any>();

    if (!inventory) {
      return json({
        id:
          order.id,

        status:
          "paid",

        product:
          order.name,

        amountCents:
          order.amount_cents,

        delivered:
          false
      });
    }

    const account =
      await decrypt(
        inventory.account_encrypted,
        env.ENCRYPTION_KEY
      );

    const discordUrl =
      env.DISCORD_URL ||
      DEFAULT_DISCORD_URL;

    const thankYouMessage =
`✅ Pagamento aprovado!
🔒 Sua conta: ${account}
🎁 Seu produto foi entregue automaticamente.
❤️ Obrigado pela compra na ONYX!
⭐ Deixe seu feedback no nosso Discord:
${discordUrl}`;

    return json({
      id:
        order.id,

      status:
        "paid",

      delivered:
        true,

      product:
        order.name,

      amountCents:
        order.amount_cents,

      account,

      discordUrl,

      thankYouMessage
    });
  }

  /* =======================================================
     WEBHOOK
  ======================================================= */

  if (
    request.method === "POST" &&
    path ===
      "/api/livepix/webhook"
  ) {
    return handleLivepixWebhook(
      request,
      env
    );
  }

  /* =======================================================
     ADMIN
  ======================================================= */

  if (
    path.startsWith(
      "/api/admin/"
    )
  ) {
    if (
      !adminAuthorized(
        request,
        env
      )
    ) {
      return json(
        {
          error:
            "Não autorizado."
        },
        401
      );
    }
  }

  /* =======================================================
     ADMIN PRODUTOS
  ======================================================= */

  if (
    request.method === "GET" &&
    path ===
      "/api/admin/products"
  ) {
    const products =
      await env.DB.prepare(
        `SELECT
          p.*,

          (
            SELECT COUNT(*)
            FROM inventory i
            WHERE i.product_id=p.id
              AND i.status='available'
          ) AS stock,

          (
            SELECT COUNT(*)
            FROM inventory i
            WHERE i.product_id=p.id
              AND i.status='sold'
          ) AS sold

         FROM products p

         ORDER BY
           p.created_at DESC`
      ).all();

    return json(
      products.results
    );
  }

  /* =======================================================
     ADMIN CRIAR PRODUTO
  ======================================================= */

  if (
    request.method === "POST" &&
    path ===
      "/api/admin/products"
  ) {
    const body =
      await request.json<any>();

    const name =
      String(
        body?.name ||
        ""
      ).trim();

    const description =
      String(
        body?.description ||
        ""
      ).trim();

    const price =
      Number(
        body?.price
      );

    if (
      !name ||
      !Number.isFinite(
        price
      ) ||
      price <= 0
    ) {
      return json(
        {
          error:
            "Nome e preço válidos são obrigatórios."
        },
        400
      );
    }

    const productId =
      id("prd");

    await env.DB.prepare(
      `INSERT INTO products
       (
         id,
         name,
         description,
         price_cents,
         active
       )
       VALUES
       (?, ?, ?, ?, 1)`
    )
      .bind(
        productId,
        name,
        description,
        Math.round(
          price * 100
        )
      )
      .run();

    return json(
      {
        id:
          productId
      },
      201
    );
  }

  /* =======================================================
     ADMIN EXCLUIR / DESATIVAR PRODUTO
  ======================================================= */

  if (
    request.method === "DELETE" &&
    path.startsWith("/api/admin/products/")
  ) {
    const productId =
      decodeURIComponent(
        path.slice("/api/admin/products/".length)
      );

    if (!productId) {
      return json(
        {
          error:
            "Produto inválido."
        },
        400
      );
    }

    const product =
      await env.DB.prepare(
        `SELECT id, name
         FROM products
         WHERE id=?
         LIMIT 1`
      )
        .bind(productId)
        .first<any>();

    if (!product) {
      return json(
        {
          error:
            "Produto não encontrado."
        },
        404
      );
    }

    /*
     * Não apagamos fisicamente o produto.
     * Apenas desativamos (active=0), para preservar
     * pedidos, estoque e histórico de vendas.
     *
     * Assim ele deixa de aparecer na loja, mas os
     * pedidos antigos continuam funcionando.
     */
    await env.DB.prepare(
      `UPDATE products
       SET active=0
       WHERE id=?`
    )
      .bind(productId)
      .run();

    return json({
      ok: true,
      id: productId,
      name: product.name
    });
  }

  /* =======================================================
     ADMIN ESTOQUE
  ======================================================= */

  if (
    request.method === "POST" &&
    path ===
      "/api/admin/stock"
  ) {
    const body =
      await request.json<any>();

    const productId =
      String(
        body?.productId ||
        ""
      );

    const account =
      String(
        body?.account ||
        ""
      ).trim();

    if (
      !productId ||
      !account
    ) {
      return json(
        {
          error:
            "Produto e conta são obrigatórios."
        },
        400
      );
    }

    const product =
      await env.DB.prepare(
        `SELECT id
         FROM products
         WHERE id=?
         LIMIT 1`
      )
        .bind(
          productId
        )
        .first<any>();

    if (!product) {
      return json(
        {
          error:
            "Produto não encontrado."
        },
        404
      );
    }

    const encrypted =
      await encrypt(
        account,
        env.ENCRYPTION_KEY
      );

    const inventoryId =
      id("inv");

    await env.DB.prepare(
      `INSERT INTO inventory
       (
         id,
         product_id,
         account_encrypted,
         status
       )
       VALUES
       (?, ?, ?, 'available')`
    )
      .bind(
        inventoryId,
        productId,
        encrypted
      )
      .run();

    return json(
      {
        id:
          inventoryId
      },
      201
    );
  }

  /* =======================================================
     ADMIN PEDIDOS
  ======================================================= */

  if (
    request.method === "GET" &&
    path ===
      "/api/admin/orders"
  ) {
    const orders =
      await env.DB.prepare(
        `SELECT
          o.id,
          o.status,
          o.amount_cents,
          o.livepix_id,
          o.livepix_reference,
          o.created_at,
          o.paid_at,
          p.name AS product
         FROM orders o
         JOIN products p
           ON p.id=o.product_id
         ORDER BY
           o.created_at DESC
         LIMIT 100`
      ).all();

    return json(
      orders.results
    );
  }

  return json(
    {
      error:
        "Rota não encontrada."
    },
    404
  );
}

/* =========================================================
   WORKER
========================================================= */

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url =
      new URL(
        request.url
      );

    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {
      try {
        return await api(
          request,
          env,
          url
        );
      } catch (error) {
        console.error(
          "Erro interno:",
          error
        );

        return json(
          {
            error:
              "Erro interno do servidor."
          },
          500
        );
      }
    }

    return env.ASSETS.fetch(
      request
    );
  }
};
