"""
brotli2scan.py - find web servers affected by HTTP2Shell (CVE-2026-111497),
the memory corruption bug in the Brotli decompressor.
Part of shouldipanic.ch.

HTTP2Shell is in the Brotli DECODER: a server is exposed when it unpacks Brotli
data it receives, e.g. request bodies sent with "Content-Encoding: br"
(Express 5 / body-parser 2 does this by default). It hits Node.js, Bun, Python
apps using the Brotli/brotlicffi packages, Envoy with the Brotli decompressor,
.NET and everything linking an old libbrotlidec. Compressing outgoing pages with
Brotli is not affected.

For each IP/host it first runs a TCP connect scan of 20 common web ports
(-p all for all 65535). It then discovers the vhosts on each IP (TLS
certificates, redirects, reverse DNS, passive DNS, certificate transparency,
optionally your own name list) and checks every vhost on that IP.
On every open port it sends ONE normal GET request to "/" (following up to 5
redirects) and looks at response headers, cookies and HTML to find the platform
(Node.js, Bun, .NET, Envoy, Python).

--send-brotli (-b) additionally sends two small POST requests to the page:
one with a VALID Brotli body (the 6 bytes that encode "{}") and one with an
unknown Content-Encoding. If the server refuses the unknown encoding but
accepts Brotli, it unpacks Brotli request bodies. Only valid, harmless data is
ever sent, never the malformed data that triggers the bug.
Only scan systems you are authorized to check.

Usage (results are printed to the terminal):
    python3 brotli2scan.py 203.0.113.10               # 20 web ports + vhost discovery (default)
    python3 brotli2scan.py 203.0.113.10 -b            # + Brotli test request on every endpoint
    python3 brotli2scan.py 198.51.100.0/24            # whole IP range
    python3 brotli2scan.py 203.0.113.10 -p all        # all 65535 TCP ports
    python3 brotli2scan.py api.example.ch@203.0.113.10    # one known vhost on a specific IP
    python3 brotli2scan.py https://api.example.ch/v1/orders -b   # test a specific API endpoint
    python3 brotli2scan.py 203.0.113.0/24 --names domains.txt  # + your own hostnames
    python3 brotli2scan.py 203.0.113.10 -d            # debug: requests, matches, probe answers
    python3 brotli2scan.py -U                         # refresh the fingerprint database

Targets can be IPs, CIDR ranges, hostnames, URLs, or a file with one per line.
The Brotli test works best against an endpoint that reads JSON bodies (an API
route): give its URL as target. A start page that ignores POST bodies can't tell.

Status:
    VULNERABLE           the platform version is visible and older than the fix
    LIKELY VULNERABLE    (-b) the server unpacks Brotli request bodies: update
                         unless you know the platform is patched
    POSSIBLY VULNERABLE  a platform that includes the Brotli decoder, version hidden
    PATCHED              the platform version is visible and includes the fix
    NOT DETECTED         nothing affected visible
    SNI ONLY       HTTPS server that only answers for its hostnames; see vhost results
    NOT HTTP       open port, but not a web server (shown with -a)
    ERROR          host not reachable / no open port (shown with -a)
"""
# check module for panic-core: everything specific to brotli2scan.
# panic-core/bundle.py turns this file plus the engine into brotli2scan.py.
from engine import *  # noqa: F401,F403  # bundle: strip

NAME = "brotli2scan"
VERSION = "1.1.1"
DESCRIPTION = "Find web servers affected by HTTP2Shell (CVE-2026-111497, Brotli decoder bug)."
# database: these platforms and every technology that runs on them
TARGETS = {"Node.js", "Microsoft ASP.NET", "Envoy", "Python"}
BUILTIN_LABEL = "platform rules"
APPS_LABEL = "TECHNOLOGIES"
COLUMNS = ["target", "final_url", "http_status", "verdict", "platform_version", "technologies",
           "server", "evidence"]

BANNER = r"""
    ____  ____  ____  ________    _______  _____ _________    _   __
   / __ )/ __ \/ __ \/_  __/ /   /  _/__ \/ ___// ____/   |  / | / /
  / __  / /_/ / / / / / / / /    / / __/ /\__ \/ /   / /| | /  |/ /
 / /_/ / _, _/ /_/ / / / / /____/ / / __/___/ / /___/ ___ |/ /|  /
/_____/_/ |_|\____/ /_/ /_____/___//____/____/\____/_/  |_/_/ |_/
"""
BANNER_COLOR = "33"
BANNER_TAGS = ["HTTP2Shell / CVE-2026-111497  ::  Brotli decoder bug",
               "port scan  ::  vhosts  ::  platform fingerprinting"]

# (technology, where, regex). A capture group is the technology's version.
FINGERPRINTS = [
    # Node.js and frameworks that only run on it
    ("Node.js", "header", r"^x-powered-by:[^\n]*\bnode(?:\.?js)?(?:/v?(\d+\.\d+\.\d+))?\b"),
    ("Node.js", "header", r"^server:[^\n]*\bnode(?:\.?js)?(?:/v?(\d+\.\d+\.\d+))?\b"),
    ("Express", "header", r"^x-powered-by:\s*express\b"),
    ("Express", "cookie", r"\bconnect\.sid="),
    ("Next.js server", "header", r"^x-powered-by:\s*next\.js ?(\d[\d.]*)?"),
    ("Next.js server", "header", r"^x-nextjs-(?:cache|prerender|matched-path|stale-time):"),
    ("Nuxt server", "header", r"^x-powered-by:\s*nuxt\b"),
    ("SvelteKit", "header", r"^x-sveltekit-page:"),
    ("Remix", "header", r"^x-remix-response:"),
    ("Koa", "header", r"^x-powered-by:\s*koa\b"),
    ("Koa", "cookie", r"\bkoa[.:]sess(?:ion)?(?:\.sig)?="),
    ("Sails.js", "cookie", r"\bsails\.sid="),
    ("Meteor", "body", r"__meteor_runtime_config__"),
    ("Strapi", "header", r"^x-powered-by:\s*strapi\b"),
    ("Ghost", "header", r"^x-ghost-cache-status:"),
    ("Bun", "header", r"^server:\s*bun\b"),
    ("Bun", "header", r"^x-powered-by:[^\n]*\b(?:bun|elysia|hono)\b"),
    # .NET (Core) - includes System.IO.Compression.Brotli
    ("ASP.NET Core", "header", r"^server:\s*kestrel\b"),
    ("ASP.NET Core", "cookie", r"\.AspNetCore\."),
    ("Blazor", "body", r"_framework/blazor\.(?:web|server|webassembly)\.js"),
    (".NET Framework", "header", r"^x-aspnet-version:\s*(\d[\d.]*)"),
    (".NET Framework", "header", r"^x-aspnetmvc-version:"),
    # Envoy / Istio
    ("Envoy", "header", r"^server:\s*envoy\b"),
    ("Envoy", "header", r"^x-envoy-[a-z-]+:"),
    ("Istio", "header", r"^server:\s*istio-envoy\b"),
    # Python servers (affected only with the Brotli / brotlicffi packages)
    ("Python", "header", r"^server:[^\n]*\bpython/(\d+\.\d+(?:\.\d+)?)"),
    ("aiohttp", "header", r"^server:[^\n]*\baiohttp/(\d[\d.]*)"),
    ("Tornado", "header", r"^server:\s*tornadoserver/?(\d[\d.]*)?"),
    ("Gunicorn", "header", r"^server:\s*gunicorn/?(\d[\d.]*)?"),
    ("Uvicorn", "header", r"^server:\s*uvicorn\b"),
    ("Hypercorn", "header", r"^server:\s*hypercorn\b"),
    ("Werkzeug", "header", r"^server:\s*werkzeug/?(\d[\d.]*)?"),
    ("Daphne", "header", r"^server:\s*daphne\b"),
    ("Django", "cookie", r"\b(?:csrftoken|django_language)="),
    ("Flask", "cookie", r"^session=\.?eJ"),
]

# "X always runs on Y" in addition to the database's 'implies'
IMPLIES = {
    "Express": ["Node.js"], "Next.js server": ["Node.js"], "Nuxt server": ["Node.js"],
    "SvelteKit": ["Node.js"], "Remix": ["Node.js"], "Koa": ["Node.js"], "Sails.js": ["Node.js"],
    "Meteor": ["Node.js"], "Strapi": ["Node.js"], "Ghost": ["Node.js"],
    "ASP.NET Core": [".NET"], "Blazor": [".NET"], "Kestrel": [".NET"],
    "Istio": ["Envoy"],
    "aiohttp": ["Python"], "Tornado": ["Python"], "Gunicorn": ["Python"], "Uvicorn": ["Python"],
    "Hypercorn": ["Python"], "Werkzeug": ["Python"], "Daphne": ["Python"], "Django": ["Python"],
    "Flask": ["Python"], "FastAPI": ["Python"],
}

# technology -> platform whose Brotli decoder matters (order = display order)
PLATFORMS = ["Node.js", "Bun", ".NET", "Envoy", "Python"]
PLATFORM_OF = {"Node.js": "Node.js", "Bun": "Bun", ".NET": ".NET", "ASP.NET Core": ".NET",
               "Kestrel": ".NET", "Blazor": ".NET", "Envoy": "Envoy", "Istio": "Envoy", "Python": "Python"}

# HTTP2Shell (CVE-2026-111497): first fixed release per supported branch
FIXED = {
    "Node.js": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},   # other lines: end of life
    "Bun": {"1": "1.4.4"},
    "Envoy": {"1.37": "1.37.8", "1.38": "1.38.6", "1.39": "1.39.3", "1.40": "1.40.0"},
}
FIXED_TABLE = [   # shown on the web page: (software, versions, note, platform)
    ("Node.js", "22.23.4, 24.22.1, 26.12.1", "older release lines get no fix", "Node.js"),
    ("Bun", "1.4.4", "", "Bun"),
    ("Envoy", "1.37.8, 1.38.6, 1.39.3, 1.40.0", "", "Envoy"),
    ("Python Brotli / brotlicffi", "1.2.1 / 1.2.1.0", "", "Python"),
    ("Brotli library (libbrotlidec)", "1.0.10, 1.1.1, 1.2.1", "", ""),
    (".NET", "", "Microsoft's next security update, see their advisory", ".NET"),
]

# the probe: Brotli encoding of the 2 bytes "{}" (made with brotli.compress, checked
# with brotli.decompress) - a complete, valid stream, nothing malformed
BROTLI_JSON = b"\x8b\x00\x80{}\x03"
UNKNOWN_ENCODING = "x-brotli2scan-test"


def version_tuple(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def platform_status(platform, version):
    """'patched', 'vulnerable' or '' (unknown) for a visible platform version."""
    if not version or platform not in FIXED:
        return ""
    branches = FIXED[platform]
    v = version_tuple(version)
    for branch, fixed in branches.items():
        if v[:len(version_tuple(branch))] == version_tuple(branch):
            return "patched" if v >= version_tuple(fixed) else "vulnerable"
    if platform == "Node.js":
        return "vulnerable"                    # 20, 23, 25 and older: end of life, no fix
    if platform == "Envoy" and v < version_tuple("1.37"):
        return "vulnerable"                    # unsupported lines
    return ""


def platforms_found(info):
    """[(platform, via-technology or '', version)] in display order."""
    found = {}
    for t in info["techs"]:
        p = PLATFORM_OF.get(t)
        if p and p not in found:
            found[p] = "" if t == p else t
    for t, by in info["implied"].items():
        p = PLATFORM_OF.get(t)
        if p and p not in found:
            found[p] = by
    # .NET Framework alone (X-AspNet-Version) has no Brotli: not a platform here
    out = []
    for p in PLATFORMS:
        if p in found:
            ver = info["versions"].get(p, "")
            out.append((p, found[p], ver))
    return out


def probe(info):
    """Send two tiny POST requests to the final page: valid Brotli vs. an unknown encoding."""
    url, log, timeout = info["final"], info["log"], info["timeout"]
    pin = info["pin"] or None

    def post(encoding, body):
        conn, resp = http_request(url, timeout, pin, method="POST", body=body, headers={
            "Content-Type": "application/json", "Content-Encoding": encoding,
            "Content-Length": str(len(body))})
        try:
            resp.read(4096)
            return resp.status
        finally:
            conn.close()

    log(f"  probe: POST {url} with a valid Brotli body ({len(BROTLI_JSON)} bytes = '{{}}')")
    br = post("br", BROTLI_JSON)
    log(f"  probe: -> HTTP {br}; same request with Content-Encoding: {UNKNOWN_ENCODING}")
    unknown = post(UNKNOWN_ENCODING, b"{}")
    log(f"  probe: -> HTTP {unknown}")
    if unknown == 415 and br != 415 and br < 500:
        result = "decodes"
    elif br == 415 and unknown == 415:
        result = "rejects"
    elif br == unknown:
        result = "ignored"
    else:
        result = "differs"
    info["probe"] = {"result": result, "br_status": br, "unknown_status": unknown, "url": url}
    info["evidence"].append(f"probe:{result} (br {br}, unknown {unknown})")
    log(f"  probe: {result}")


def verdict(info):
    """(verdict, version, technologies) for the result row."""
    plats = platforms_found(info)
    states = [(p, v, platform_status(p, v)) for p, _, v in plats]
    for p, via, _ in plats:
        if via:
            info["evidence"].append(f"{p}:via {via}")
    version = ", ".join(f"{p} {v}" for p, v, _ in states if v)
    if any(s == "vulnerable" for _, _, s in states):
        v = "VULNERABLE"
    elif states and all(s == "patched" for _, _, s in states):
        v = "PATCHED"
    elif (info.get("probe") or {}).get("result") == "decodes":
        v = "LIKELY VULNERABLE"
    elif plats:
        v = "POSSIBLY VULNERABLE"
    else:
        v = "NOT DETECTED"
    techs = [p for p, _, _ in plats] + [t for t in info["techs"] if t not in PLATFORMS]
    techs = [f"{t} {info['versions'][t]}" if t in info["versions"] and t not in PLATFORMS else t
             for t in dict.fromkeys(techs)]
    return v, version, techs


def count_key(v):
    return v


def verdict_style(row):
    """(rank, colour, status, reason) for the result list."""
    v, version, techs, evidence = row[3], row[4], row[5], row[7]
    plats = [t for t in techs.split(", ") if t in PLATFORMS]
    probe = re.search(r"probe:(\w+)", evidence)
    probe = probe.group(1) if probe else ""
    if v == "VULNERABLE":
        bad = []
        for item in version.split(", "):
            p, _, ver = item.rpartition(" ")
            if platform_status(p, ver) == "vulnerable":
                fixed = FIXED.get(p, {}).get(".".join(ver.split(".")[:1 if p in ("Node.js", "Bun") else 2]))
                bad.append(f"{p} {ver} < {fixed}" if fixed else f"{p} {ver} (end of life)")
        return 10, "red", v, ", ".join(bad) or version
    if v == "LIKELY VULNERABLE":
        return 12, "red", v, "unpacks Brotli request bodies" + (f" ({', '.join(plats)})" if plats else "")
    if v == "POSSIBLY VULNERABLE":
        if plats == ["Python"]:
            return 22, "yellow", v, "Python: only with the Brotli package"
        return 20, "yellow", v, f"{', '.join(plats)}, version hidden"
    if v == "PATCHED":
        return 40, "green", v, version
    if v == "NOT DETECTED":
        return 50, "plain", v, "refuses Brotli request bodies" if probe == "rejects" else ""
    return None


EXAMPLES = """examples:
  brotli2scan.py 203.0.113.10                        20 web ports + every vhost on the IP
  brotli2scan.py 203.0.113.10 -b                     + Brotli test request on every website
  brotli2scan.py https://api.example.ch/v1/orders -b test one API route (best for -b)
  brotli2scan.py 198.51.100.0/24 --names domains.txt a whole range + your own hostnames
  brotli2scan.py 203.0.113.10 -p all -o out.csv      all 65535 ports, results also as CSV

status: VULNERABLE (version visible, without the fix) - LIKELY VULNERABLE (-b: server
unpacks Brotli it receives) - POSSIBLY VULNERABLE (affected platform, version hidden) -
PATCHED - NOT DETECTED
"""


def add_arguments(ap):
    g = ap.add_argument_group("HTTP2Shell test")
    g.add_argument("-b", "--send-brotli", action="store_true",
                   help="also send two tiny POST requests to every website: one with VALID Brotli "
                        "data, one with an unknown encoding. Shows whether the server unpacks Brotli "
                        "it receives (that's what HTTP2Shell attacks). Harmless data only, never the "
                        "bug trigger. Works best with an API URL as target")


def options_from_args(a):
    if a.send_brotli:
        print("Brotli test: on (2 small POST requests per endpoint, valid data only)",
              file=sys.stderr, flush=True)
    return {"probe": True} if a.send_brotli else {}


# ---------------------------------------------------------------------------
# web page (web.py): assessment shown to visitors
# ---------------------------------------------------------------------------
CONSENT_VERSION = "2026-10-27.1"   # bump whenever the consent / rules text on the page changes

WHERE = {"via": "always runs on it"}

NOTES = {
    "Node.js": "Node.js brings its own copy of Brotli, so updating the system library alone doesn't "
               "fix it. Update Node.js and restart the app.",
    "Bun": "Bun brings its own copy of Brotli. Update Bun and rebuild apps made with "
           "bun build --compile.",
    ".NET": ".NET includes its own Brotli. Install Microsoft's security update for the .NET runtime "
            "as soon as it is out and restart the app.",
    "Envoy": "Only Envoy setups with the Brotli decompressor are affected. Update Envoy (or the Istio "
             "release that ships it); turning the filter off is a stopgap, not a fix, if a service "
             "behind it unpacks the data itself.",
    "Python": "Python itself has no Brotli. Only apps using the Brotli or brotlicffi package are "
              "affected, for example aiohttp servers that unpack compressed requests. "
              "Check with pip show Brotli brotlicffi.",
}
NOTE_GENERAL = ("Many other programs include Brotli too (curl, Java via brotli4j, Go via "
                "andybalholm/brotli). Update the system's Brotli package as well.")

PROBE_TEXT = {
    "decodes": ("Your server unpacked the Brotli data we sent and refused the unknown encoding. "
                "It decodes Brotli it receives, which is exactly what HTTP2Shell attacks."),
    "rejects": ("Your server refused Brotli data on this page (HTTP 415). It does not seem to unpack "
                "Brotli request bodies here. Other pages or API routes may behave differently."),
    "ignored": ("Your server answered both test requests the same way, so this page ignores the data "
                "we sent. That doesn't tell whether other routes (for example an API) unpack Brotli."),
    "differs": ("Your server answered the Brotli request differently from the unknown one "
                "(HTTP {br} vs {unknown}). That can mean it unpacks Brotli, but it's not conclusive."),
    "error": "The Brotli test request failed: {detail}.",
}


def web_options(data):
    return {"probe": True} if data.get("probe") is True else {}


def web_result(host, ip, row, info, friendly_evidence):
    _, final, status, verdict_, version, techs, server, evidence = row
    result = {"host": host, "ip": ip, "final_url": final, "http_status": status,
              "reachable": verdict_ not in ("ERROR", "SNI ONLY"), "verdict": verdict_,
              "server": server, "platforms": [], "technologies": [], "evidence": [],
              "fixed": [], "notes": [], "probe": None, "error": ""}
    if verdict_ == "ERROR":
        result["error"] = evidence
    if verdict_ == "SNI ONLY":
        result["error"] = "The server refused the HTTPS connection for this hostname."
    if not result["reachable"] or not info:
        result["status"] = {"level": "unknown", "title": "Not reachable",
                            "text": "We couldn't load this website."}
        return result

    plats = platforms_found(info)
    result["platforms"] = [{"name": p, "via": via, "version": v, "state": platform_status(p, v)}
                           for p, via, v in plats]
    result["technologies"] = [t for t in techs.split(", ") if t]
    ev = []
    for e in friendly_evidence(", ".join(x for x in info["evidence"]
                                         if not x.startswith(("probe:",)) and ":via " not in x)):
        ev.append(e)
    for p, via, _ in plats:
        if via:
            ev.append(f"{p}: {via} always runs on {p}")
    result["evidence"] = ev
    found = {p for p, _, _ in plats}
    result["fixed"] = [{"software": s, "versions": v, "note": n, "found": bool(p and p in found)}
                       for s, v, n, p in FIXED_TABLE]
    result["notes"] = [NOTES[p] for p in PLATFORMS if p in found] + ([NOTE_GENERAL] if found else [])

    pr = info.get("probe")
    if pr:
        text = PROBE_TEXT[pr["result"]].format(br=pr.get("br_status"), unknown=pr.get("unknown_status"),
                                               detail=pr.get("detail", ""))
        result["probe"] = {"result": pr["result"], "text": text}

    names = ", ".join(p for p, _, _ in plats)
    named = " and ".join([", ".join(p for p, _, _ in plats[:-1]), plats[-1][0]]) if len(plats) > 1 \
        else names
    if verdict_ == "VULNERABLE":
        bad = [f"{p} {v}" for p, _, v in plats if platform_status(p, v) == "vulnerable"]
        st = {"level": "bad", "title": "Vulnerable",
              "text": f"This site runs {', '.join(bad)}, which doesn't include the HTTP2Shell fix. "
                      "Update it and restart the app."}
    elif verdict_ == "PATCHED":
        st = {"level": "good", "title": "Patched",
              "text": f"The visible version of {named} includes the HTTP2Shell fix."}
    elif verdict_ == "LIKELY VULNERABLE":
        st = {"level": "bad", "title": "Likely vulnerable",
              "text": "Your server unpacks Brotli data it receives. Make sure "
                      + (f"{named} and " if plats else "")
                      + "its Brotli library run one of the fixed versions below."}
    elif verdict_ == "POSSIBLY VULNERABLE":
        st = {"level": "warn", "title": "Possibly vulnerable",
              "text": f"{named} {'is' if len(plats) == 1 else 'are'} affected by HTTP2Shell, but this "
                      "site doesn't reveal the exact version. Make sure it runs one of the fixed "
                      "versions below."}
        if found == {"Python"}:
            st["text"] = ("This site runs on Python. Python is only affected when an app uses the "
                          "Brotli or brotlicffi package. If yours does, update it to a fixed version.")
    else:
        st = {"level": "good", "title": "Nothing affected found",
              "text": "We found no sign of Node.js, Bun, .NET, Envoy or Python on this site. Software "
                      "that doesn't reveal itself can't be seen from outside, though."}
        if pr and pr["result"] == "rejects":
            st["text"] += " Your server also refused Brotli data in our test."
    result["status"] = st
    return result


def web_timeout_result(host, ip):
    return {"host": host, "ip": ip, "reachable": False, "verdict": "ERROR",
            "error": "The website took too long to respond.", "platforms": [], "technologies": [],
            "evidence": [], "fixed": [], "notes": [], "probe": None,
            "status": {"level": "unknown", "title": "Not reachable",
                       "text": "The website took too long to respond."}}


def audit_fields(result):
    outcome = result.get("verdict", "ERROR").lower().replace(" ", "-")
    if outcome in ("error", "sni-only"):
        outcome = "unreachable"
    return {"outcome": outcome, "platforms": [p["name"] for p in result.get("platforms", [])],
            "probe": (result.get("probe") or {}).get("result")}
