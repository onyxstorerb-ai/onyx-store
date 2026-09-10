export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ADMIN_PASSWORD: string;
  ENCRYPTION_KEY: string;
  LIVEPIX_API_TOKEN: string;
  DISCORD_URL?: string;
  SITE_URL?: string;
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });

function id(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

function adminAuthorized(request: Request, env: Env) {
  return request.headers.get("x-admin-password") === env.ADMIN_PASSWORD;
}

async function keyFromSecret(secret: string) {
  const bytes = new TextEncoder().encode(secret);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encrypt(text: string, secret: string) {
  const key = await keyFromSecret(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text)
  );
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...result));
}

async function decrypt(value: string, secret: string) {
  const raw = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const iv = raw.slice(0, 12);
  const data = raw.slice(12);
  const key = await keyFromSecret(secret);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(decrypted);
}

async function livepixCreateDonation(
  env: Env,
  amountCents: number,
  description: string,
  orderId: string,
  origin: string
) {
  const amount = amountCents / 100;
  const webhook = `${origin}/api/livepix/webhook`;
  const returnUrl = `${origin}/?paid=${encodeURIComponent(orderId)}`;

  const response = await fetch("https://livepix.cc/api/donations", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.LIVEPIX_API_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      description,
      amount,
      webhook,
      return_url: returnUrl,
      metadata: { order_id: orderId }
    })
  });

  const body = await response.json<any>();
  if (!response.ok) {
    throw new Error(body?.message || body?.error || "Falha ao criar cobrança LivePix");
  }
  return body.data;
}

async function verifyLivepixDonation(env: Env, donationId: string) {
  const response = await fetch(`https://livepix.cc/api/donations/${encodeURIComponent(donationId)}`, {
    headers: { Authorization: `Bearer ${env.LIVEPIX_API_TOKEN}` }
  });
  if (!response.ok) return null;
  const body = await response.json<any>();
  return body.data ?? null;
}

async function reserveInventory(env: Env, orderId: string, productId: string) {
  const inventoryId = id("inv");

  // D1 executa o batch como uma operação transacional.
  // O UPDATE só escolhe uma conta ainda disponível.
  const result = await env.DB.batch([
    env.DB.prepare(
      `UPDATE inventory
       SET status='reserved', order_id=?
       WHERE id = (
         SELECT id FROM inventory
         WHERE product_id=? AND status='available'
         ORDER BY created_at ASC
         LIMIT 1
       )`
    ).bind(orderId, productId),
    env.DB.prepare(
      `SELECT id FROM inventory WHERE order_id=? AND status='reserved' LIMIT 1`
    ).bind(orderId)
  ]);

  const row = result[1]?.results?.[0] as any;
  if (!row) return null;
  return row.id as string;
}

async function markPaidAndDeliver(env: Env, donation: any) {
  const orderId = donation?.metadata?.order_id;
  if (!orderId) return { ok: false, reason: "missing_order_id" };

  const order = await env.DB.prepare(
    `SELECT * FROM orders WHERE id=? LIMIT 1`
  ).bind(orderId).first<any>();

  if (!order) return { ok: false, reason: "order_not_found" };
  if (order.status === "paid") return { ok: true, alreadyPaid: true };

  // Verificação dupla: consulta a cobrança diretamente na API.
  const verified = await verifyLivepixDonation(env, donation.id);
  if (!verified?.proof) return { ok: false, reason: "payment_not_verified" };

  const inventory = await env.DB.prepare(
    `SELECT * FROM inventory WHERE id=? AND order_id=? LIMIT 1`
  ).bind(order.inventory_id, order.id).first<any>();

  if (!inventory) return { ok: false, reason: "reserved_inventory_not_found" };

  const account = await decrypt(inventory.account_encrypted, env.ENCRYPTION_KEY);

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE orders SET status='paid', livepix_id=?, livepix_reference=?, paid_at=CURRENT_TIMESTAMP WHERE id=? AND status!='paid'`
    ).bind(donation.id, donation.reference ?? null, order.id),
    env.DB.prepare(
      `UPDATE inventory SET status='sold', sold_at=CURRENT_TIMESTAMP WHERE id=? AND status='reserved'`
    ).bind(inventory.id)
  ]);

  return { ok: true, account, orderId: order.id };
}

async function api(request: Request, env: Env, url: URL) {
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/products") {
    const products = await env.DB.prepare(
      `SELECT p.id,p.name,p.description,p.price_cents,
        (SELECT COUNT(*) FROM inventory i WHERE i.product_id=p.id AND i.status='available') AS stock
       FROM products p WHERE p.active=1 ORDER BY p.created_at DESC`
    ).all();
    return json(products.results);
  }

  if (request.method === "POST" && path === "/api/checkout") {
    const body = await request.json<any>();
    const productId = String(body.productId || "");

    const product = await env.DB.prepare(
      `SELECT * FROM products WHERE id=? AND active=1 LIMIT 1`
    ).bind(productId).first<any>();

    if (!product) return json({ error: "Produto não encontrado." }, 404);

    const orderId = id("ord");
    const inventoryId = await reserveInventory(env, orderId, product.id);

    if (!inventoryId) {
      return json({ error: "Produto sem estoque." }, 409);
    }

    await env.DB.prepare(
      `INSERT INTO orders(id,product_id,inventory_id,amount_cents,status) VALUES(?,?,?,?, 'pending')`
    ).bind(orderId, product.id, inventoryId, product.price_cents).run();

    try {
      const donation = await livepixCreateDonation(
        env,
        product.price_cents,
        `ONYX - ${product.name}`,
        orderId,
        url.origin
      );

      await env.DB.prepare(
        `UPDATE orders SET livepix_id=?, livepix_reference=? WHERE id=?`
      ).bind(donation.id, donation.reference ?? null, orderId).run();

      return json({
        orderId,
        checkout: donation.checkout,
        pixCode: donation.pix_code ?? null,
        pixQrCode: donation.pix_qr_code ?? null,
        expiresAt: donation.pix_code_expires_at ?? null
      }, 201);
    } catch (error) {
      await env.DB.batch([
        env.DB.prepare(`UPDATE inventory SET status='available', order_id=NULL WHERE id=? AND status='reserved'`).bind(inventoryId),
        env.DB.prepare(`UPDATE orders SET status='cancelled' WHERE id=?`).bind(orderId)
      ]);
      return json({ error: error instanceof Error ? error.message : "Erro no pagamento." }, 502);
    }
  }

  if (request.method === "GET" && path.startsWith("/api/order/")) {
    const orderId = path.split("/").pop()!;
    const order = await env.DB.prepare(
      `SELECT o.id,o.status,o.amount_cents,p.name
       FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id=? LIMIT 1`
    ).bind(orderId).first<any>();

    if (!order) return json({ error: "Pedido não encontrado." }, 404);

    if (order.status !== "paid") return json({
      id: order.id,
      status: order.status,
      product: order.name
    });

    const inventory = await env.DB.prepare(
      `SELECT account_encrypted FROM inventory WHERE order_id=? LIMIT 1`
    ).bind(order.id).first<any>();

    if (!inventory) return json({ id: order.id, status: "paid", delivered: false });

    const account = await decrypt(inventory.account_encrypted, env.ENCRYPTION_KEY);

    return json({
      id: order.id,
      status: "paid",
      delivered: true,
      product: order.name,
      account
    });
  }

  if (request.method === "POST" && path === "/api/livepix/webhook") {
    const payload = await request.json<any>();

    if (payload?.event === "donation.created") return json({ status: "ok" });
    if (payload?.event !== "donation.paid") return json({ error: "Evento desconhecido" }, 400);

    const result = await markPaidAndDeliver(env, payload.data);
    if (!result.ok) return json(result, 400);

    return json({ status: "ok" });
  }

  if (path.startsWith("/api/admin/")) {
    if (!adminAuthorized(request, env)) return json({ error: "Não autorizado." }, 401);
  }

  if (request.method === "GET" && path === "/api/admin/products") {
    const products = await env.DB.prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM inventory i WHERE i.product_id=p.id AND i.status='available') stock,
              (SELECT COUNT(*) FROM inventory i WHERE i.product_id=p.id AND i.status='sold') sold
       FROM products p ORDER BY p.created_at DESC`
    ).all();
    return json(products.results);
  }

  if (request.method === "POST" && path === "/api/admin/products") {
    const body = await request.json<any>();
    const productId = id("prd");
    await env.DB.prepare(
      `INSERT INTO products(id,name,description,price_cents,active) VALUES(?,?,?,?,1)`
    ).bind(
      productId,
      String(body.name || "Produto"),
      String(body.description || ""),
      Math.round(Number(body.price) * 100)
    ).run();
    return json({ id: productId }, 201);
  }

  if (request.method === "POST" && path === "/api/admin/stock") {
    const body = await request.json<any>();
    const productId = String(body.productId || "");
    const account = String(body.account || "").trim();
    if (!productId || !account) return json({ error: "Produto e conta são obrigatórios." }, 400);

    const encrypted = await encrypt(account, env.ENCRYPTION_KEY);
    const inventoryId = id("inv");
    await env.DB.prepare(
      `INSERT INTO inventory(id,product_id,account_encrypted,status) VALUES(?,?,?,'available')`
    ).bind(inventoryId, productId, encrypted).run();

    return json({ id: inventoryId }, 201);
  }

  if (request.method === "GET" && path === "/api/admin/orders") {
    const orders = await env.DB.prepare(
      `SELECT o.id,o.status,o.amount_cents,o.livepix_id,o.created_at,o.paid_at,p.name product
       FROM orders o JOIN products p ON p.id=o.product_id
       ORDER BY o.created_at DESC LIMIT 100`
    ).all();
    return json(orders.results);
  }

  return json({ error: "Rota não encontrada." }, 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env, url);
      } catch (error) {
        console.error(error);
        return json({ error: "Erro interno do servidor." }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
