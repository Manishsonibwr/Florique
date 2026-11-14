/* Shared cart for every page.
 *  - Logged-in users: the cart is stored on the server (per user), via /api/cart.
 *  - Guests: the cart is kept in this browser (localStorage) until they log in,
 *    then it is merged into their server cart and removed from the browser.
 *
 * Usage:  Cart.ready.then(() => { const items = Cart.items(); ... });
 *         Cart.save(items);  Cart.count();  Cart.refresh();  Cart.forget();
 */
(function () {
  const GUEST_KEY  = "flowerShopGuestCart";
  const LEGACY_KEY = "flowerShopCart"; // old key shared by everyone on a browser; no longer used

  let loggedIn = false;
  let isReady = false;
  let current = [];
  let queue = Promise.resolve(); // serialises server writes so they can't arrive out of order

  function clean(list) {
    return Array.isArray(list)
      ? list.filter(i => i && typeof i.price === "number" && typeof i.qty === "number" && i.qty > 0)
            .map(i => ({ id: i.id, name: i.name, price: i.price, qty: i.qty }))
      : [];
  }

  function readGuest() {
    try { return clean(JSON.parse(localStorage.getItem(GUEST_KEY))); } catch (e) { return []; }
  }
  function writeGuest(list) {
    try {
      if (list.length) localStorage.setItem(GUEST_KEY, JSON.stringify(list));
      else localStorage.removeItem(GUEST_KEY);
    } catch (e) { console.error("Could not save cart:", e); }
  }

  async function api(method, url, list) {
    const opts = { method, credentials: "same-origin", cache: "no-store" };
    if (list) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify({ items: list });
    }
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(method + " " + url + " -> " + res.status);
    return clean((await res.json()).items);
  }

  async function load() {
    try { localStorage.removeItem(LEGACY_KEY); } catch (e) {}

    let me = null;
    try {
      const r = await fetch("/api/auth/me", { credentials: "same-origin", cache: "no-store" });
      if (r.ok) me = await r.json();
    } catch (e) {}
    loggedIn = !!(me && me.user);

    if (loggedIn) {
      const guest = readGuest();
      try {
        current = guest.length ? await api("POST", "/api/cart/merge", guest) : await api("GET", "/api/cart");
        if (guest.length) writeGuest([]);
      } catch (e) {
        console.error("Could not load cart:", e);
        current = [];
      }
    } else {
      current = readGuest();
    }
    isReady = true;
  }

  const ready = load();

  window.Cart = {
    ready,
    isReady: () => isReady,
    isLoggedIn: () => loggedIn,
    items: () => current.map(i => ({ ...i })),
    count: () => current.reduce((s, i) => s + i.qty, 0),
    total: () => current.reduce((s, i) => s + i.qty * i.price, 0),

    save(list) {
      current = clean(list);
      if (loggedIn) {
        const snapshot = current.map(i => ({ ...i }));
        queue = queue.then(() => api("PUT", "/api/cart", snapshot)).catch(e => console.error("Could not save cart:", e));
      } else {
        writeGuest(current);
      }
    },

    // Re-read the cart from its source of truth (e.g. when the tab regains focus)
    async refresh() {
      await ready;
      await queue;
      try { current = loggedIn ? await api("GET", "/api/cart") : readGuest(); } catch (e) {}
      return window.Cart.items();
    },

    // Call on sign-out: drop anything cached in this browser
    forget() {
      try { localStorage.removeItem(GUEST_KEY); localStorage.removeItem(LEGACY_KEY); } catch (e) {}
      current = [];
      loggedIn = false;
    },
  };
})();
