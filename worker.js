// Cloudflare Worker – HTTP Basic Auth gate
// Protects every request (pages + assets) before serving from static assets.

const BASIC_USER = "azx72289";
const BASIC_PASS = "2255";

function unauthorized() {
  return new Response("401 – Authorization Required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Protected Site"',
      "Content-Type": "text/plain;charset=UTF-8",
    },
  });
}

export default {
  async fetch(request, env) {
    const authHeader = request.headers.get("Authorization");

    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return unauthorized();
    }

    const encoded = authHeader.slice("Basic ".length);
    let decoded;
    try {
      decoded = atob(encoded);
    } catch {
      return unauthorized();
    }

    const [user, ...passParts] = decoded.split(":");
    const pass = passParts.join(":");

    if (user !== BASIC_USER || pass !== BASIC_PASS) {
      return unauthorized();
    }

    return env.ASSETS.fetch(request);
  },
};
