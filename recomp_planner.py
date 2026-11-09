"""Sort the games on an Xbox card by what it would take to play them natively on PC.

Reads titles only. It never opens a game container, and it has no decryption code.
Network calls send Store IDs and game titles to Microsoft, Steam and GOG, and fetch one
public tracker page. A failed lookup is reported as "not checked", never as "none".

Sources, each used only as a lookup:
  Microsoft display catalog, Steam store search, GOG catalog,
  and the unofficial tracker at https://portedgames.com/recompiled-games/

Run: python recomp_planner.py [--disk N] [--refresh] [--out DIR] [--open]
"""
import argparse
import html
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime

TRACKER_URL = "https://portedgames.com/recompiled-games/"
CATALOG_URL = "https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds=%s&market=US&languages=en-US"
STEAM_URL = "https://store.steampowered.com/api/storesearch/?term=%s&l=english&cc=US"
GOG_URL = "https://catalog.gog.com/v1/catalog?limit=20&query=like%%3A%s"
GITHUB_URL = "https://api.github.com/repos/%s"
USER_AGENT = "disk-reader-recomp-planner"
TRACKER_MAX_AGE = 24 * 3600
BC_FAMILY = "xbox360backwardcompatibil"
STORE_PROBE = "Quake"  # sold on Steam and GOG; a search that misses it is treated as broken
PLAYABLE = {"Working", "Beta"}
COUNTED_METHODS = {"Static recompilation", "Decompilation", "Game-specific runtime"}
STOP_WORDS = {"the", "a", "an", "of", "and"}

TIERS = [
    ("project-playable", "A project already exists",
     "The tracker lists a Working or Beta project. Start here instead of building anything."),
    ("project-early", "A project has started",
     "The tracker lists only early or offline work. Check it before starting your own."),
    ("candidate-pc", "Best new targets: older game with a PC release",
     "No exact project found, and a PC version turned up, which avoids console encryption. GOG sells its games "
     "DRM-free, so those are listed first. Check the license, and DRM on other stores."),
    ("candidate-console", "Harder targets: older game, no PC release found",
     "No exact project or PC version found. You would need a readable copy from the original console."),
    ("modern", "Not recompilation targets",
     "Packaged for Xbox One or Series rather than as a backward-compatible title. Look for an official PC version."),
]
TIER_ORDER = {key: i for i, (key, _, _) in enumerate(TIERS)}
ERA_LABELS = {"original-xbox": "Original Xbox", "xbox-360": "Xbox 360",
              "backward-compatible": "Older Xbox (backward-compatible)",
              "xbox-one": "Xbox One package", "series": "Xbox Series package", "unknown": "Not known"}


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url):
    return json.loads(fetch(url))


def normalize(title):
    """A comparison key. Keeps 'definitive edition', since a remaster is not the original game."""
    text = unicodedata.normalize("NFKD", re.sub("[™®©]", "", title))
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    text = re.sub(r"\([^)]*\)", " ", text)
    text = re.sub(r"\bfor xbox one\b|\bcomplete\s*$", " ", text.strip())
    text = re.sub(r"[^\w\s]", "", text.replace("-", " ").replace("–", " "))
    return " ".join(text.split())


def _text(fragment):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", fragment)).split())


def parse_tracker(page):
    """Project rows from the tracker page. Raises ValueError if the layout is not recognised."""
    rows = []
    for m in re.finditer(r'<tr id="row-[^"]+".*?</tr>', page, flags=re.S):
        row = m.group(0)
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.S)
        if len(cells) < 7:
            continue
        name = re.match(r"(.*?)(?=<div|$)", cells[0], flags=re.S).group(1)
        note = re.search(r'class="r-note"[^>]*>(.*?)</div>', cells[0], flags=re.S)
        link = re.search(r'href="([^"]+)"', cells[6])
        url = urllib.parse.urljoin(TRACKER_URL, html.unescape(link.group(1))) if link else ""
        rows.append({"game": _text(name), "console": _text(cells[1]), "project": _text(cells[2]),
                     "method": _text(cells[3]), "status": _text(cells[4]),
                     "note": _text(note.group(1)) if note else "", "url": url})
    if not rows:
        raise ValueError("the tracker page layout was not recognised")
    return rows


def match_tracker(title, rows):
    """(exact projects, related projects). Related rows share a series, not the same game."""
    key = normalize(title)
    words = [w for w in key.split() if w not in STOP_WORDS]
    series = " ".join(words[:2]) if len(words) >= 2 else None
    exact, related = [], []
    for row in rows:
        if row["method"] not in COUNTED_METHODS:
            continue
        other = normalize(row["game"])
        if other == key:
            exact.append(row)
        elif series and " ".join(w for w in other.split() if w not in STOP_WORDS).startswith(series):
            if row["game"] not in (r["game"] for r in related):
                related.append(row)
    return exact, related[:4]


def era_of(product):
    family = (product.get("family") or "").lower()
    released = (product.get("released") or "")[:10]
    if family.startswith(BC_FAMILY):
        if not released:
            return "backward-compatible"
        year = released[:4]  # 2005 straddles the Xbox 360 launch, so it stays unlabelled
        return "original-xbox" if year < "2005" else "xbox-360" if year > "2005" else "backward-compatible"
    if "ConsoleGen9" in (product.get("optimized") or []):
        return "series"
    if product.get("optimized"):
        return "xbox-one"
    return "unknown"


def parse_products(data):
    """Microsoft catalog response to {store id: facts}."""
    out = {}
    for p in data.get("Products", []):
        props = p.get("Properties") or {}
        market = (p.get("MarketProperties") or [{}])[0]
        out[p.get("ProductId", "")] = {"family": props.get("PackageFamilyName") or "",
                                       "optimized": props.get("XboxConsoleGenOptimized") or [],
                                       "released": market.get("OriginalReleaseDate") or ""}
    return out


def pc_name_matches(title, name):
    key, other = normalize(title), normalize(name)
    return other == key or other in (key + " complete edition", key + " the complete edition")


def classify(game, rows):
    """Add era, tier, projects and notes to a game dict holding title, product and pc facts."""
    era = era_of(game["product"]) if game.get("product") else "unknown"
    exact, related = match_tracker(game["title"], rows) if rows is not None else ([], [])
    playable = [r for r in exact if r["status"] in PLAYABLE]
    pc_found = game.get("pc", {}).get("steam") or game.get("pc", {}).get("gog")
    if playable:
        tier = "project-playable"
    elif exact:
        tier = "project-early"
    elif era in ("xbox-one", "series"):
        tier = "modern"
    elif pc_found:
        tier = "candidate-pc"
    else:
        tier = "candidate-console"
    game.update(era=era, tier=tier, exact=exact, related=related)
    return game


def load_titles(args):
    """Game titles as [{store, title}], from the card or from the viewer's saved catalog."""
    import xbox_card  # imported here so the matching logic and tests need no disk code
    if args.disk is not None:
        model = xbox_card.read_card(args.disk, progress=lambda msg: print(" ", msg))
        catalog, _ = xbox_card.fetch_catalog([t["store"] for t in model["titles"]], xbox_card.load_cache())
        xbox_card.save_cache(catalog)
        xbox_card.apply_catalog(model, catalog)
        games = [{"store": t["store"], "title": t["title"]} for t in model["titles"] if t["kind"] == "Game"]
        return games, "Disk %d, read just now" % args.disk
    saved = xbox_card.load_cache()
    games = [{"store": store, "title": xbox_card.clean_title(v.get("title", ""))}
             for store, v in saved.items() if v.get("kind") == "Game" and v.get("title")]
    return games, "Card Viewer's saved catalog, which may include games since removed from the card"


SEARCH_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError)


class Lookups:
    """Network lookups with a cache file. Only successful answers are cached."""

    def __init__(self, path, refresh=False):
        self.path = path
        self.data = {}
        self.working = {}
        if not refresh:
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                pass
        for section in ("products", "steam", "gog", "repos"):
            self.data.setdefault(section, {})

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=1)

    def tracker(self):
        """(rows or None, when fetched). Falls back to an older copy if the fetch fails."""
        saved = self.data.get("tracker") or {}
        if saved.get("rows") and time.time() - saved.get("at", 0) < TRACKER_MAX_AGE:
            return saved["rows"], saved["at"]
        try:
            rows = parse_tracker(fetch(TRACKER_URL).decode("utf-8", "replace"))
        except (OSError, ValueError):
            return (saved.get("rows"), saved.get("at")) if saved.get("rows") else (None, None)
        self.data["tracker"] = {"rows": rows, "at": time.time()}
        return rows, self.data["tracker"]["at"]

    def products(self, store_ids):
        missing = [s for s in store_ids if s and s not in self.data["products"]]
        for i in range(0, len(missing), 15):
            try:
                self.data["products"].update(parse_products(fetch_json(CATALOG_URL % ",".join(missing[i:i + 15]))))
            except (OSError, ValueError):
                pass
        return self.data["products"]

    def _search(self, url, title, names_of):
        names = names_of(fetch_json(url % urllib.parse.quote(normalize(title))))
        return [n for n in names if pc_name_matches(title, n)]

    def _store_search(self, section, url, title, names_of):
        """A list of matching store names, or None if the store could not be asked."""
        if section not in self.working:
            try:
                self.working[section] = bool(self._search(url, STORE_PROBE, names_of))
            except SEARCH_ERRORS:
                self.working[section] = False
        if not self.working[section]:  # checked before the cache, so a broken store is reported as such
            return None
        if title in self.data[section]:
            return self.data[section][title]
        try:
            found = self._search(url, title, names_of)
        except SEARCH_ERRORS:
            return None
        self.data[section][title] = found
        return found

    def steam(self, title):
        return self._store_search("steam", STEAM_URL, title, lambda j: [x["name"] for x in j["items"]])

    def gog(self, title):
        return self._store_search("gog", GOG_URL, title, lambda j: [x["title"] for x in j["products"]])

    def repo(self, url):
        """Live GitHub facts for a project link, or None if not GitHub or not reachable."""
        m = re.match(r"https://github\.com/([^/]+/[^/#?]+)", url or "")
        if not m:
            return None
        name = m.group(1).removesuffix(".git")
        if name in self.data["repos"]:
            return self.data["repos"][name]
        try:
            j = fetch_json(GITHUB_URL % name)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return None
            facts = {"missing": True}
        except (OSError, ValueError):
            return None
        else:
            facts = {"stars": j.get("stargazers_count"), "pushed": (j.get("pushed_at") or "")[:10],
                     "archived": bool(j.get("archived"))}
        self.data["repos"][name] = facts
        return facts


def gather(games, lookups):
    rows, tracker_at = lookups.tracker()
    products = lookups.products([g["store"] for g in games])
    for g in games:
        g["product"] = products.get(g["store"])
        g["pc"] = {"steam": lookups.steam(g["title"]), "gog": lookups.gog(g["title"])}
        classify(g, rows)
        for r in g["exact"]:
            r["repo"] = lookups.repo(r["url"])
    games.sort(key=lambda g: (TIER_ORDER[g["tier"]], not g["pc"].get("gog"), g["title"].lower()))
    return {"games": games, "tracker_at": tracker_at, "tracker_rows": len(rows or []),
            "tracker_ok": rows is not None}


def safe_url(url):
    return url if re.match(r"https?://", url or "") else ""


def pc_text(pc):
    """Plain wording that keeps 'no match found' apart from 'could not check'."""
    parts = []
    for label, key in (("Steam", "steam"), ("GOG", "gog")):
        value = pc.get(key)
        parts.append("%s: %s" % (label, "not checked" if value is None else ("found" if value else "no title match")))
    return ", ".join(parts)


def project_html(row):
    e = html.escape
    url = safe_url(row.get("url"))
    name = '<a href="%s" rel="noopener noreferrer" target="_blank">%s</a>' % (e(url, quote=True), e(row["project"])) \
        if url else e(row["project"])
    repo = row.get("repo")
    facts = ""
    if repo and repo.get("missing"):
        facts = ' · <span class="warn">repo not found on GitHub</span>'
    elif repo:
        facts = " · %s stars, last push %s%s" % (e(str(repo.get("stars"))), e(repo.get("pushed") or "unknown"),
                                                 ", archived" if repo.get("archived") else "")
    return '<li>%s <span class="pill">%s</span> <span class="muted">%s · %s%s</span></li>' % (
        name, e(row["status"]), e(row["console"]), e(row["method"]), facts)


def game_html(g):
    e = html.escape
    projects = "".join(project_html(r) for r in g["exact"])
    needs = ""
    if g["exact"]:
        consoles = sorted({r["console"] for r in g["exact"]})
        needs = '<p class="muted">Needs a copy from: %s. The encrypted file on this card will not work.</p>' \
            % e(", ".join(consoles))
    related = ""
    if g["related"]:
        related = '<p class="muted">Related, but a different game or version: %s</p>' % e(
            "; ".join("%s (%s)" % (r["game"], r["console"]) for r in g["related"]))
    released = (g.get("product") or {}).get("released", "")[:4]
    return ('<article><h3>%s</h3><p class="muted">%s%s · %s</p>%s%s%s</article>' % (
        e(g["title"]), e(ERA_LABELS[g["era"]]), " · listed " + e(released) if released else "",
        e(pc_text(g["pc"])), '<ul>%s</ul>' % projects if projects else "", needs, related))


def render(plan, source):
    e = html.escape
    sections = []
    for key, heading, blurb in TIERS:
        games = [g for g in plan["games"] if g["tier"] == key]
        if games:
            sections.append("<section><h2>%s <span class=\"count\">%d</span></h2><p>%s</p>%s</section>" % (
                e(heading), len(games), e(blurb), "".join(game_html(g) for g in games)))
    if plan["tracker_ok"]:
        tracker = "%d projects from %s, fetched %s" % (
            plan["tracker_rows"], TRACKER_URL, datetime.fromtimestamp(plan["tracker_at"]).strftime("%Y-%m-%d %H:%M"))
    else:
        tracker = "The tracker could not be read, so no projects are shown. Run this again before trusting the groups."
    return PAGE % {"count": len(plan["games"]), "source": e(source), "tracker": e(tracker),
                   "sections": "".join(sections)}


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Recomp Plan</title><style>
:root{color-scheme:light dark;--bg:#f6f6f4;--card:#fff;--ink:#1d1f21;--muted:#5d6266;--line:#dcdcd6;--accent:#107c10;--warn:#a4400a}
@media(prefers-color-scheme:dark){:root{--bg:#141516;--card:#1e2022;--ink:#ececea;--muted:#a3a8ac;--line:#34373a;--accent:#6ccb5f;--warn:#f0a070}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:auto;padding:32px 16px 64px}h1{font-size:30px;margin:0 0 8px}
h2{font-size:21px;margin:36px 0 4px}h3{font-size:16px;margin:0}section>p{margin:0 0 12px;color:var(--muted)}
article{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:8px 0}
article p{margin:2px 0}ul{margin:8px 0;padding-left:18px}a{color:var(--accent)}.muted{color:var(--muted);font-size:14px}
.warn{color:var(--warn)}.pill{font-size:12px;border:1px solid var(--line);border-radius:99px;padding:1px 8px}
.count{color:var(--muted);font-weight:400}.notice{border-left:3px solid var(--accent);padding:2px 12px;margin:16px 0}
</style></head><body><main><h1>Recomp Plan</h1><p>%(count)d games sorted by what it would take to play them natively on PC.</p>
<div class="notice"><p><strong>The card's files aren't the source.</strong> They are encrypted, and this tool does not open them.
Any project below needs a readable copy of the game, obtained separately and legally.</p></div>
%(sections)s<h2>How to read this</h2><ul class="muted">
<li>Titles: %(source)s.</li><li>Projects: %(tracker)s. That's an unofficial tracker, and nothing here was tested. Only exact title matches count.</li>
<li>The original console is inferred from Microsoft's package family and release date, so check it for any game you pick.</li>
<li>"No title match" means a store search by this exact name found nothing. The game may be sold under another name, in a collection, or have been delisted.</li>
<li>Check any download yourself before running it. Listing here is not a safety or legal judgment.</li></ul>
</main></body></html>"""


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--disk", type=int, help="read this physical disk (needs an admin prompt) instead of the saved catalog")
    ap.add_argument("--refresh", action="store_true", help="ignore saved lookups")
    ap.add_argument("--out", default=os.path.join(here, "plans"), help="folder for the report")
    ap.add_argument("--open", action="store_true", help="open the report when done")
    args = ap.parse_args()

    games, source = load_titles(args)
    if not games:
        print("No games found. Open Card Viewer once with the card connected, or pass --disk N.")
        return 1
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    lookups = Lookups(os.path.join(root, "disk-reader", "planner_cache.json"), refresh=args.refresh)
    print("Checking %d games..." % len(games))
    plan = gather(games, lookups)
    lookups.save()

    os.makedirs(args.out, exist_ok=True)
    page = os.path.join(args.out, "recomp_plan.html")
    with open(page, "w", encoding="utf-8") as f:
        f.write(render(plan, source))
    with open(os.path.join(args.out, "recomp_plan.json"), "w", encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=1)
    for key, heading, _ in TIERS:
        names = [g["title"] for g in plan["games"] if g["tier"] == key]
        print("%s (%d): %s" % (heading, len(names), "; ".join(names) or "none"))
    print("Report:", page)
    if args.open:
        webbrowser.open(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
