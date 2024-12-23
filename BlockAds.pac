// Regular expression patterns for popular ad domains and subdomains
var adRegex = new RegExp(
    "^(.+[-_.])?(ad[sxv]?|teads?|doubleclick|adservice|adtrack(er|ing)?|advertising|adnxs|admeld|advert|adx(addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr[ao]|adinterax|admarvel|admed(ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(it|ity)|adtraxx|advertising|aff(iliat(es?|ion))|akamaihd|amazon-adsystem|appnexus|appsflyer|audience2media|bingads|bidswitch|brightcove|casalemedia|contextweb|criteo|doubleclick|emxdgt|e-planning|exelator|eyewonder|flashtalking|goog(le(syndication|tagservices))|gunggo|hurra(h|ynet)|imrworldwide|insightexpressai|kontera|lifestreetmedia|lkntracker|mediaplex|ooyala|openx|pixel(e|junky)|popcash|propellerads|pubmatic|quantserve|revcontent|revenuehits|sharethrough|skimresources|taboola|traktrafficx|twitter[.]com|undertone|yieldmo)",
    "i"
);

// Define blocked URLs (exact matches)
var blockedURLs = [
    "discord.com/channels/889102180332732436",
    "discord.com/channels/452237221840551938",
    "discord.com/channels/1128414431085346897",
    "discord.com/channels/567592181905489920",
    "discord.com/channels/549448381613998103",
    "discord.com/channels/150662382874525696",
    "discord.com/channels/731641286389661727",
    "discord.com/channels/246414844851519490",
    "discord.com/channels/240880736851329024",
    "reddit.com/r/croatia",
    "reddit.com/r/hrvatska"
];

// Define blocked sites (exact domain matches)
var blockedSites = [
    "instrumenttactics.com",
    "srce.unizg.hr",
    "rtl.hr",
    "hrt.hr",
    "dnevnik.hr",
    "novatv.dnevnik.hr",
    "novavideo.dnevnik.hr",
    "forum.hr",
    "forum.pcekspert.com"
];

function FindProxyForURL(url, host) {
    // Normalize to lowercase for consistent comparisons
    url = url.toLowerCase();
    host = host.toLowerCase();

    // Block explicit URLs
    if (blockedURLs.includes(url)) {
        return "PROXY 127.0.0.1";
    }

    // Block explicit domains
    if (blockedSites.includes(host) || blockedSites.some(site => host.endsWith("." + site))) {
        return "PROXY 127.0.0.1";
    }

    // Explicit blocks for Google Ad services
    if (
        shExpMatch(host, "googleads.g.doubleclick.net") ||
        shExpMatch(host, "*.googleads.g.doubleclick.net") ||
        shExpMatch(host, "pagead2.googlesyndication.com") ||
        shExpMatch(host, "*.pagead2.googlesyndication.com") ||
        shExpMatch(host, "tpc.googlesyndication.com") ||
        shExpMatch(host, "*.tpc.googlesyndication.com") ||
        shExpMatch(host, "partner.googleadservices.com") ||
        shExpMatch(host, "*.partner.googleadservices.com") ||
        shExpMatch(host, "ad.doubleclick.net") ||
        shExpMatch(host, "*.ad.doubleclick.net") ||
        shExpMatch(host, "ads.youtube.com") ||
        shExpMatch(host, "*.ads.youtube.com") ||
        shExpMatch(host, "m.youtube.com") || // Block mobile YouTube ads
        shExpMatch(host, "*.m.youtube.com")
    ) {
        return "PROXY 127.0.0.1";
    }

    // Block based on the general ad regex
    if (adRegex.test(host)) {
        return "PROXY 127.0.0.1";
    }

    // If no ads or blocked sites/URLs are matched, connect directly
    return "DIRECT";
}
