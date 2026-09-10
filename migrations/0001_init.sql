CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price_cents INTEGER NOT NULL CHECK(price_cents > 0),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inventory (
  id TEXT PRIMARY KEY,
  product_id TEXT NOT NULL,
  account_encrypted TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available'
    CHECK(status IN ('available','reserved','sold')),
  order_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sold_at TEXT,
  FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  product_id TEXT NOT NULL,
  inventory_id TEXT,
  amount_cents INTEGER NOT NULL,
  livepix_id TEXT,
  livepix_reference TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','paid','cancelled')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT,
  FOREIGN KEY(product_id) REFERENCES products(id),
  FOREIGN KEY(inventory_id) REFERENCES inventory(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_livepix_id
  ON orders(livepix_id)
  WHERE livepix_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_inventory_product_status
  ON inventory(product_id, status);

CREATE INDEX IF NOT EXISTS idx_orders_status
  ON orders(status);
