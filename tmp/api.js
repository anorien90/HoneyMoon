// Optimized API wrappers with consistent error handling, timeout, and retry logic.  
// Fixed: AbortController and timer now properly reset per retry attempt.  

export async function apiGet(path, opts = {}) {
  const timeout = opts.timeout || 12000;
  const retries = opts.retries || 1;
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(path, { signal: controller.signal });
      clearTimeout(timer);
      const data = await res.json().catch(() => null);
      return { ok: res.ok, status: res.status, data, error: data?.error || null };
    } catch (err) {
      clearTimeout(timer);
      lastError = err. name === 'AbortError' ? 'Request timeout' : (err.message || 'Network error');
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
  }
  return { ok: false, status: 0, data: null, error: lastError };
}

export async function apiPost(path, body = {}, opts = {}) {
  const timeout = opts.timeout || 120000;
  const retries = opts.retries || 1;
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      clearTimeout(timer);
      const data = await res.json().catch(() => null);
      return { ok: res.ok, status: res.status, data, error: data?.error || null };
    } catch (err) {
      clearTimeout(timer);
      lastError = err.name === 'AbortError' ? 'Request timeout' : (err. message || 'Network error');
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
  }
  return { ok: false, status: 0, data:  null, error: lastError };
}

