export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

  ADMIN_PASSWORD: string;
  ENCRYPTION_KEY: string;

  // Mantido para não quebrar o ambiente atual.
  LIVEPIX_API_TOKEN: string;

  // Nome exatamente igual ao Secret do Cloudflare.
  LIVEPIX_CLIENT_ID: string;
  LIVEPIX_CLIENT_SECRET: string;

  DISCORD_URL?: string;
  SITE_URL?: string;
}

const LIVEPIX_OAUTH_URL = "https://oauth.livepix.gg/oauth2/token";
const LIVEPIX_API_URL = "https://api.livepix.gg/v2";

// Taxa considerada para o cálculo do valor cobrado.
const LIVEPIX_FEE_PERCENT = 5;

let oauthCache: {
  accessToken: string;
  expiresAt: number;
} | null = null;

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8"
    }
  });

function id(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

function adminAuthorized(request: Request, env: Env) {
  return request.headers.get("x-admin-password") === env.ADMIN_PASSWORD;
}

async function keyFromSecret(secret: string) {
  const bytes = new TextEncoder().encode(secret);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    bytes
  );

  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text: string, secret: string) {
  const key = await keyFromSecret(secret);

  const iv = crypto.getRandomValues(
    new Uint8Array(12)
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    new TextEncoder().encode(text)
  );

  const result = new Uint8Array(
    iv.length + encrypted.byteLength
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

async function decrypt(value: string, secret: string) {
  const raw = Uint8Array.from(
    atob(value),
    c => c.charCodeAt(0)
  );

  const iv = raw.slice(0, 12);
  const data = raw.slice(12);

  const key = await keyFromSecret(secret);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

function amountWithFee(amountCents: number) {
  const fee = LIVEPIX_FEE_PERCENT / 100;

  if (fee <= 0 || fee >= 1) {
    throw new Error("Taxa LivePix inválida.");
  }

  return Math.ceil(
    amountCents / (1 - fee)
  );
}

async function getLivepixAccessToken(env: Env) {
  // CORRIGIDO:
  // O Cloudflare usa LIVEPIX_CLIENT_ID.
  if (
    !env.LIVEPIX_CLIENT_ID ||
    !env.LIVEPIX_CLIENT_SECRET
  ) {
    throw new Error(
      "Credenciais OAuth2 do LivePix não configuradas."
    );
  }

  const now = Date.now();

  if (
    oauthCache &&
    oauthCache.expiresAt > now + 60_000
  ) {
    return oauthCache.accessToken;
  }

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: env.LIVEPIX_CLIENT_ID,
    client_secret: env.LIVEPIX_CLIENT_SECRET,
    scope: "payments:write payments:read"
  });

  const response = await fetch(
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

  const data = await response.json<any>();

  if (
    !response.ok ||
    !data?.access_token
  ) {
    throw new Error(
      data?.error_description ||
      data?.message ||
      "Falha ao autenticar no LivePix."
    );
  }

  oauthCache = {
    accessToken: data.access_token,
    expiresAt:
      now +
      Number(data.expires_in || 3600) * 1000
  };

  return data.access_token as string;
}

async function livepixRequest(
  env: Env,
  path: string,
  init: RequestInit = {}
) {
  const accessToken =
    await getLivepixAccessToken(env);

  const headers = new Headers(
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
    !headers.has("Content-Type")
  ) {
    headers.set(
      "Content-Type",
      "application/json"
    );
  }

  let response = await fetch(
    `${LIVEPIX_API_URL}${path}`,
    {
      ...init,
      headers
    }
  );

  // Token expirado: gera outro e tenta novamente.
  if (response.status === 401) {
    oauthCache = null;

    const retryToken =
      await getLivepixAccessToken(env);

    headers.set(
      "Authorization",
      `Bearer ${retryToken}`
    );

    response = await fetch(
      `${LIVEPIX_API_URL}${path}`,
      {
        ...init,
        headers
      }
    );
  }

  return response;
}

async function livepixCreatePayment(
  env: Env,
  amountCents: number,
  description: string,
  orderId: string,
  origin: string
) {
  const chargedAmountCents =
    amountWithFee(amountCents);

  const redirectUrl =
    `${origin}/?paid=${encodeURIComponent(orderId)}`;

  const response =
    await livepixRequest(
      env,
      "/payments",
      {
        method: "POST",
        body: JSON.stringify({
          amount: chargedAmountCents,
          currency: "BRL",
          redirectUrl
        })
      }
    );

  const body =
    await response.json<any>();

  if (!response.ok) {
    throw new Error(
      body?.message ||
      body?.error_description ||
      body?.error ||
      "Falha ao criar pagamento LivePix."
    );
  }

  const payment = body?.data;

  if (
    !payment?.reference ||
    !payment?.redirectUrl
  ) {
    throw new Error(
      "Resposta inválida do LivePix ao criar o pagamento."
    );
  }

  return {
    ...payment,
    description,
    chargedAmountCents,
    orderId
  };
}

async function verifyLivepixPayment(
  env: Env,
  paymentId: string
) {
  const response =
    await livepixRequest(
      env,
      `/payments/${encodeURIComponent(paymentId)}`
    );

  if (!response.ok) {
    return null;
  }

  const body =
    await response.json<any>();

  return body?.data ?? null;
}

async function findLivepixPaymentByReference(
  env: Env,
  reference: string
) {
  const query = new URLSearchParams({
    reference,
    limit: "10"
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
    Array.isArray(body?.data)
      ? body.data
      : [];

  return (
    payments.find(
      (payment: any) =>
        payment?.reference === reference
    ) ??
    payments[0] ??
    null
  );
}

async function reserveInventory(
  env: Env,
  orderId: string,
  productId: string
) {
  const inventoryId = id("inv");

  const result =
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE inventory
         SET status='reserved', order_id=?
         WHERE id = (
           SELECT id
           FROM inventory
           WHERE product_id=?
             AND status='available'
           ORDER BY created_at ASC
           LIMIT 1
         )`
      ).bind(
        orderId,
        productId
      ),

      env.DB.prepare(
        `SELECT id
         FROM inventory
         WHERE order_id=?
           AND status='reserved'
         LIMIT 1`
      ).bind(orderId)
    ]);

  const row =
    result[1]?.results?.[0] as any;

  if (!row) {
    return null;
  }

  return row.id as string;
}

async function markPaidAndDeliver(
  env: Env,
  payment: any
) {
  const reference =
    String(payment?.reference || "");

  if (!reference) {
    return {
      ok: false,
      reason: "missing_reference"
    };
  }

  const order =
    await env.DB.prepare(
      `SELECT *
       FROM orders
       WHERE livepix_reference=?
       LIMIT 1`
    )
      .bind(reference)
      .first<any>();

  if (!order) {
    return {
      ok: false,
      reason: "order_not_found"
    };
  }

  if (order.status === "paid") {
    return {
      ok: true,
      alreadyPaid: true
    };
  }

  const verified =
    payment?.id
      ? await verifyLivepixPayment(
          env,
          String(payment.id)
        )
      : await findLivepixPaymentByReference(
          env,
          reference
        );

  if (!verified?.proof) {
    return {
      ok: false,
      reason: "payment_not_verified"
    };
  }

  if (verified.currency !== "BRL") {
    return {
      ok: false,
      reason: "invalid_currency"
    };
  }

  if (
    Number(verified.amount) !==
    Number(order.amount_cents)
  ) {
    return {
      ok: false,
      reason: "amount_mismatch"
    };
  }

  const inventory =
    await env.DB.prepare(
      `SELECT *
       FROM inventory
       WHERE id=?
         AND order_id=?
       LIMIT 1`
    )
      .bind(
        order.inventory_id,
        order.id
      )
      .first<any>();

  if (!inventory) {
    return {
      ok: false,
      reason: "reserved_inventory_not_found"
    };
  }

  const account =
    await decrypt(
      inventory.account_encrypted,
      env.ENCRYPTION_KEY
    );

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE orders
       SET status='paid',
           livepix_id=?,
           livepix_reference=?,
           paid_at=CURRENT_TIMESTAMP
       WHERE id=?
         AND status!='paid'`
    ).bind(
      String(
        verified.id ??
        payment.id ??
        ""
      ),
      reference,
      order.id
    ),

    env.DB.prepare(
      `UPDATE inventory
       SET status='sold',
           sold_at=CURRENT_TIMESTAMP
       WHERE id=?
         AND status='reserved'`
    ).bind(inventory.id)
  ]);

  return {
    ok: true,
    account,
    orderId: order.id
  };
}

async function handleLivepixWebhook(
  request: Request,
  env: Env
) {
  const payload =
    await request.json<any>();

  // CORRIGIDO:
  // Usa LIVEPIX_CLIENT_ID.
  if (
    payload?.clientId &&
    payload.clientId !==
      env.LIVEPIX_CLIENT_ID
  ) {
    return json(
      {
        error:
          "Cliente LivePix inválido."
      },
      401
    );
  }

  if (payload?.event !== "new") {
    return json({
      status: "ok"
    });
  }

  const resource =
    payload?.resource;

  const paymentId =
    String(resource?.id || "");

  const reference =
    String(resource?.reference || "");

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

  const payment =
    paymentId
      ? await verifyLivepixPayment(
          env,
          paymentId
        )
      : await findLivepixPaymentByReference(
          env,
          reference
        );

  if (!payment) {
    return json(
      {
        error:
          "Pagamento não encontrado."
      },
      404
    );
  }

  const result =
    await markPaidAndDeliver(
      env,
      payment
    );

  if (
    !result.ok &&
    result.reason ===
      "order_not_found"
  ) {
    return json(
      result,
      404
    );
  }

  if (!result.ok) {
    return json(
      result,
      400
    );
  }

  return json({
    status: "ok"
  });
}

async function api(
  request: Request,
  env: Env,
  url: URL
) {
  const path =
    url.pathname;

  // PRODUTOS
  if (
    request.method === "GET" &&
    path === "/api/products"
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
         ORDER BY p.created_at DESC`
      ).all();

    return json(
      products.results
    );
  }

  // CHECKOUT
  if (
    request.method === "POST" &&
    path === "/api/checkout"
  ) {
    const body =
      await request.json<any>();

    const productId =
      String(
        body.productId || ""
      );

    const product =
      await env.DB.prepare(
        `SELECT *
         FROM products
         WHERE id=?
           AND active=1
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

    const orderId =
      id("ord");

    const inventoryId =
      await reserveInventory(
        env,
        orderId,
        product.id
      );

    if (!inventoryId) {
      return json(
        {
          error:
            "Produto sem estoque."
        },
        409
      );
    }

    const chargedAmountCents =
      amountWithFee(
        Number(
          product.price_cents
        )
      );

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
       (?, ?, ?, ?, 'pending')`
    )
      .bind(
        orderId,
        product.id,
        inventoryId,
        chargedAmountCents
      )
      .run();

    try {
      const payment =
        await livepixCreatePayment(
          env,
          Number(
            product.price_cents
          ),
          `ONYX - ${product.name}`,
          orderId,
          url.origin
        );

      await env.DB.prepare(
        `UPDATE orders
         SET livepix_id=?,
             livepix_reference=?
         WHERE id=?`
      )
        .bind(
          payment.id ?? null,
          payment.reference,
          orderId
        )
        .run();

      return json(
        {
          orderId,
          checkout:
            payment.redirectUrl,

          pixCode: null,
          pixQrCode: null,
          expiresAt: null,

          amountCents:
            chargedAmountCents,

          baseAmountCents:
            Number(
              product.price_cents
            ),

          feePercent:
            LIVEPIX_FEE_PERCENT
        },
        201
      );
    } catch (error) {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE inventory
           SET status='available',
               order_id=NULL
           WHERE id=?
             AND status='reserved'`
        ).bind(inventoryId),

        env.DB.prepare(
          `UPDATE orders
           SET status='cancelled'
           WHERE id=?`
        ).bind(orderId)
      ]);

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

  // PEDIDO
  if (
    request.method === "GET" &&
    path.startsWith("/api/order/")
  ) {
    const orderId =
      path.split("/").pop()!;

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
        .bind(orderId)
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

    if (
      order.status !== "paid"
    ) {
      return json({
        id: order.id,
        status: order.status,
        product: order.name,
        amountCents:
          order.amount_cents
      });
    }

    const inventory =
      await env.DB.prepare(
        `SELECT account_encrypted
         FROM inventory
         WHERE order_id=?
         LIMIT 1`
      )
        .bind(order.id)
        .first<any>();

    if (!inventory) {
      return json({
        id: order.id,
        status: "paid",
        delivered: false
      });
    }

    const account =
      await decrypt(
        inventory.account_encrypted,
        env.ENCRYPTION_KEY
      );

    return json({
      id: order.id,
      status: "paid",
      delivered: true,
      product: order.name,
      amountCents:
        order.amount_cents,
      account
    });
  }

  // WEBHOOK LIVEPIX
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

  // ADMIN
  if (
    path.startsWith("/api/admin/")
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

  // ADMIN PRODUTOS
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
          ) stock,
          (
            SELECT COUNT(*)
            FROM inventory i
            WHERE i.product_id=p.id
              AND i.status='sold'
          ) sold
         FROM products p
         ORDER BY p.created_at DESC`
      ).all();

    return json(
      products.results
    );
  }

  // ADMIN CRIAR PRODUTO
  if (
    request.method === "POST" &&
    path ===
      "/api/admin/products"
  ) {
    const body =
      await request.json<any>();

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
        String(
          body.name || "Produto"
        ),
        String(
          body.description || ""
        ),
        Math.round(
          Number(body.price) * 100
        )
      )
      .run();

    return json(
      {
        id: productId
      },
      201
    );
  }

  // ADMIN ESTOQUE
  if (
    request.method === "POST" &&
    path ===
      "/api/admin/stock"
  ) {
    const body =
      await request.json<any>();

    const productId =
      String(
        body.productId || ""
      );

    const account =
      String(
        body.account || ""
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
        id: inventoryId
      },
      201
    );
  }

  // ADMIN PEDIDOS
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
          o.created_at,
          o.paid_at,
          p.name product
         FROM orders o
         JOIN products p
           ON p.id=o.product_id
         ORDER BY o.created_at DESC
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

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url =
      new URL(request.url);

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
        console.error(error);

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
