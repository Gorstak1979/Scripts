// Regular expression patterns for popular ad domains and subdomains
var adRegex = new RegExp(
    "^(.+[-_.])?(ad[sxv]?|teads?|doubleclick|adservice|adtrack(er|ing)?|advertising|adnxs|admeld|advert|adx(addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr[ao]|adinterax|admarvel|admed(ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(it|ity)|adtraxx|advertising|aff(iliat(es?|ion))|akamaihd|amazon-adsystem|appnexus|appsflyer|audience2media|bingads|bidswitch|brightcove|casalemedia|contextweb|criteo|doubleclick|emxdgt|e-planning|exelator|eyewonder|flashtalking|goog(le(syndication|tagservices))|gunggo|hurra(h|ynet)|imrworldwide|insightexpressai|kontera|lifestreetmedia|lkntracker|mediaplex|ooyala|openx|pixel(e|junky)|popcash|propellerads|pubmatic|quantserve|revcontent|revenuehits|sharethrough|skimresources|taboola|traktrafficx|twitter[.]com|undertone|yieldmo)",
    "i"
);

function FindProxyForURL(url, host) {
    // Normalize to lowercase for consistent comparisons
    url = url.toLowerCase();
    host = host.toLowerCase();

    // Explicit blocks for each pattern
    if (
        shExpMatch(url, "discord.com/channels/889102180332732436") ||
        shExpMatch(url, "discord.com/channels/452237221840551938") ||
        shExpMatch(url, "discord.com/channels/1128414431085346897") ||
        shExpMatch(url, "discord.com/channels/567592181905489920") ||
        shExpMatch(url, "discord.com/channels/549448381613998103") ||
        shExpMatch(url, "discord.com/channels/150662382874525696") ||
        shExpMatch(url, "discord.com/channels/731641286389661727") ||
        shExpMatch(url, "discord.com/channels/246414844851519490") ||
        shExpMatch(url, "discord.com/channels/240880736851329024") ||
        shExpMatch(url, "reddit.com/r/croatia") ||
        shExpMatch(url, "reddit.com/r/hrvatska") ||
        shExpMatch(host, "instrumenttactics.com") ||
        shExpMatch(host, "srce.unizg.hr") ||
        shExpMatch(host, "rtl.hr") ||
        shExpMatch(host, "hrt.hr") ||
        shExpMatch(host, "dnevnik.hr") ||
        shExpMatch(host, "novatv.dnevnik.hr") ||
        shExpMatch(host, "novavideo.dnevnik.hr") ||
        shExpMatch(host, "forum.hr") ||
        shExpMatch(host, "forum.pcekspert.com") ||
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
        shExpMatch(host, "m.youtube.com") ||
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

