// license-watch — L1 Cloudflare Worker
// Docs: https://developers.cloudflare.com/workers/runtime-apis/handlers/scheduled/
//
// Hourly entrypoint. Reads cursors from KV, posts them to Modal.com webhook,
// receives new cursors back, writes them. Modal runs the heavy Go detectors.

const SOURCES = [
  "gh_archive", "npm", "pypi", "aur", "crates", "docker_hub",
  "ecosystems", "github_code", "reddit", "hn", "lobsters",
  "mastodon", "bluesky", "dev_to", "stackexchange", "youtube",
  "hf", "artifacthub", "gitlab", "codeberg", "telegram",
];

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runDetect(env));
  },

  // Manual trigger: curl https://license-watch-scheduler.<user>.workers.dev/run
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === "/run") {
      ctx.waitUntil(runDetect(env));
      return new Response("dispatched\n", { status: 202 });
    }
    if (url.pathname === "/state") {
      const state = await readAllCursors(env);
      return new Response(JSON.stringify(state, null, 2), {
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("license-watch L1 scheduler\n");
  },
};

async function runDetect(env) {
  const cursors = await readAllCursors(env);
  const payload = {
    cursors,
    watchlist_url: env.WATCHLIST_RAW_URL,
    ts: new Date().toISOString(),
  };

  const resp = await fetch(env.MODAL_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "Modal-Key": env.MODAL_TOKEN_ID,
      "Modal-Secret": env.MODAL_TOKEN_SECRET,
      "x-gh-token": env.GH_TOKEN,
    },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    console.error(`modal webhook ${resp.status}: ${await resp.text()}`);
    return;
  }

  const result = await resp.json();
  if (result.cursors) {
    await writeAllCursors(env, result.cursors);
  }
  console.log(`detect ok — candidates=${result.candidate_count ?? "?"}`);
}

async function readAllCursors(env) {
  const out = {};
  for (const src of SOURCES) {
    out[src] = (await env.STATE.get(`cursor:${src}`)) ?? "";
  }
  return out;
}

async function writeAllCursors(env, cursors) {
  const ops = [];
  for (const [src, val] of Object.entries(cursors)) {
    if (typeof val === "string" && val.length > 0) {
      ops.push(env.STATE.put(`cursor:${src}`, val));
    }
  }
  await Promise.all(ops);
}
