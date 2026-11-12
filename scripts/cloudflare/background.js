// Cloudflare Worker "background": random Unsplash photo for the Homarr board and LittleLink backgrounds.
// GET / redirects to a random landscape photo; GET /photo.json returns one photo plus the photographer credit;
// GET /status shows the list size and the last Unsplash error (never the key).
// One API call fetches 30 photos, kept in memory for 30 minutes, so the demo limit (50 calls/hour) isn't reached.
// The Cache API doesn't work on workers.dev, hence memory. If Unsplash fails, the old list or a Bing wallpaper is used.
// Secret UNSPLASH_ACCESS_KEY (the Unsplash app's Access Key); optional text variable QUERY (default "landscape").
// Deploy: Workers & Pages > Create > Worker "background" > Edit code (paste) > Deploy; Settings > Variables and Secrets.

const REFRESH_MS = 30 * 60 * 1000;
const FALLBACK = "https://bingw.jasonzeng.dev/?index=random&w=1920";
const UTM = "utm_source=homelab_background&utm_medium=referral";

let photos = null;
let fetchedAt = 0;
let lastError = null;

async function getPhotos(env) {
  if (photos && Date.now() - fetchedAt < REFRESH_MS) return photos;
  const params = new URLSearchParams({
    count: "30",
    orientation: "landscape",
    content_filter: "high",
    query: env.QUERY || "landscape",
  });
  try {
    const res = await fetch(`https://api.unsplash.com/photos/random?${params}`, {
      headers: {
        Authorization: `Client-ID ${env.UNSPLASH_ACCESS_KEY}`,
        "Accept-Version": "v1",
        "User-Agent": "homelab-background-worker",
      },
    });
    if (!res.ok) {
      lastError = `Unsplash HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`;
      console.warn(lastError);
    } else {
      photos = (await res.json()).map((p) => ({
        // Hotlinked from images.unsplash.com, as the API guidelines require; image requests don't count as API calls
        image: `${p.urls.raw}&w=1920&h=1080&fit=crop&q=80&fm=jpg`,
        name: p.user.name,
        profile: `${p.user.links.html}?${UTM}`,
        link: `${p.links.html}?${UTM}`,
      }));
      fetchedAt = Date.now();
      lastError = null;
    }
  } catch (err) {
    // Network error: keep whatever list we had
    lastError = `Unsplash request failed: ${err}`;
    console.warn(lastError);
  }
  return photos;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!["GET", "HEAD"].includes(request.method)) {
      return new Response("Method not allowed", { status: 405 });
    }

    const list = await getPhotos(env);
    const photo = list?.length ? list[Math.floor(Math.random() * list.length)] : null;

    if (url.pathname === "/status") {
      return Response.json(
        { photos: list?.length ?? 0, ageMinutes: list ? Math.round((Date.now() - fetchedAt) / 60000) : null, lastError },
        { headers: { "Cache-Control": "no-store" } },
      );
    }
    if (url.pathname === "/photo.json") {
      return Response.json(photo ?? { image: FALLBACK }, {
        headers: { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" },
      });
    }
    if (url.pathname !== "/") {
      return new Response("Not found", { status: 404 });
    }
    // no-store: every page load gets a new photo
    return new Response(null, {
      status: 302,
      headers: { Location: photo ? photo.image : FALLBACK, "Cache-Control": "no-store" },
    });
  },
};
