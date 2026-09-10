  /* =======================================================
     ADMIN EDITAR PRODUTO
  ======================================================= */

  if (
    request.method === "PUT" &&
    path.startsWith("/api/admin/products/")
  ) {
    const productId =
      decodeURIComponent(
        path.slice("/api/admin/products/".length)
      );

    if (!productId) {
      return json(
        {
          error: "Produto inválido."
        },
        400
      );
    }

    let body: any;

    try {
      body = await request.json<any>();
    } catch {
      return json(
        {
          error: "JSON inválido."
        },
        400
      );
    }

    const name =
      String(body?.name || "").trim();

    const description =
      String(body?.description || "").trim();

    const price =
      Number(body?.price);

    if (
      !name ||
      !Number.isFinite(price) ||
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

    const product =
      await env.DB.prepare(
        `SELECT id
         FROM products
         WHERE id=?
         LIMIT 1`
      )
        .bind(productId)
        .first<any>();

    if (!product) {
      return json(
        {
          error: "Produto não encontrado."
        },
        404
      );
    }

    await env.DB.prepare(
      `UPDATE products
       SET
         name=?,
         description=?,
         price_cents=?
       WHERE id=?`
    )
      .bind(
        name,
        description,
        Math.round(price * 100),
        productId
      )
      .run();

    return json({
      success: true,
      message: "Produto atualizado."
    });
  }


  /* =======================================================
     ADMIN REMOVER / DESATIVAR PRODUTO
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
          error: "Produto inválido."
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
        .bind(productId)
        .first<any>();

    if (!product) {
      return json(
        {
          error: "Produto não encontrado."
        },
        404
      );
    }

    /*
     * Não apagamos fisicamente o produto.
     * Apenas desativamos para preservar
     * histórico de pedidos e vendas.
     */
    await env.DB.prepare(
      `UPDATE products
       SET active=0
       WHERE id=?`
    )
      .bind(productId)
      .run();

    /*
     * Estoque disponível que ainda não foi
     * vendido pode ser removido.
     */
    await env.DB.prepare(
      `DELETE FROM inventory
       WHERE product_id=?
         AND status='available'`
    )
      .bind(productId)
      .run();

    return json({
      success: true,
      message: "Produto removido da loja."
    });
  }


  /* =======================================================
     ADMIN LISTAR ESTOQUE INDIVIDUAL
  ======================================================= */

  if (
    request.method === "GET" &&
    path.startsWith("/api/admin/stock/")
  ) {
    const productId =
      decodeURIComponent(
        path.slice("/api/admin/stock/".length)
      );

    if (!productId) {
      return json(
        {
          error: "Produto inválido."
        },
        400
      );
    }

    const stock =
      await env.DB.prepare(
        `SELECT
          id,
          status,
          created_at
         FROM inventory
         WHERE product_id=?
         ORDER BY created_at ASC`
      )
        .bind(productId)
        .all();

    return json(
      stock.results
    );
  }


  /* =======================================================
     ADMIN REMOVER UNIDADE DO ESTOQUE
  ======================================================= */

  if (
    request.method === "DELETE" &&
    path.startsWith("/api/admin/stock/")
  ) {
    const inventoryId =
      decodeURIComponent(
        path.slice("/api/admin/stock/".length)
      );

    if (!inventoryId) {
      return json(
        {
          error: "Estoque inválido."
        },
        400
      );
    }

    const inventory =
      await env.DB.prepare(
        `SELECT
          id,
          status
         FROM inventory
         WHERE id=?
         LIMIT 1`
      )
        .bind(inventoryId)
        .first<any>();

    if (!inventory) {
      return json(
        {
          error: "Item de estoque não encontrado."
        },
        404
      );
    }

    /*
     * Não permite apagar uma conta que já foi
     * reservada para uma compra ou vendida.
     */
    if (
      inventory.status !== "available"
    ) {
      return json(
        {
          error:
            "Esse estoque já está reservado ou vendido e não pode ser removido."
        },
        409
      );
    }

    await env.DB.prepare(
      `DELETE FROM inventory
       WHERE id=?
         AND status='available'`
    )
      .bind(inventoryId)
      .run();

    return json({
      success: true,
      message: "Estoque removido."
    });
  }
