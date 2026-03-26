const store = new Map();

function get(key) {
  const entry = store.get(key);
  if (!entry) {
    return null;
  }

  if (entry.expiresAt <= Date.now()) {
    store.delete(key);
    return null;
  }

  return entry.value;
}

function set(key, value, ttlMs) {
  store.set(key, {
    value,
    expiresAt: Date.now() + ttlMs,
  });
  return value;
}

async function remember(key, ttlMs, loader) {
  const cached = get(key);
  if (cached !== null) {
    return cached;
  }

  const value = await loader();
  return set(key, value, ttlMs);
}

module.exports = {
  get,
  set,
  remember,
};
