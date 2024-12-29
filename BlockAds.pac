
var adRegex = new RegExp(
    "^(.+[-_.])?(ad[sxv]?|doubleclick|adservice|adtrack(er|ing)?|advertising|adnxs|admeld|advert|adx(addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr[ao]|adinterax|admarvel|admed(ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(it|ity)|adtraxx|advertising|youtube.*(ads|ad|doubleclick))",
    "i"
);

function FindProxyForURL(url, host) {
    url = url.toLowerCase();
    host = host.toLowerCase();

    // Block YouTube ads explicitly
    if (url.indexOf("youtube.com") !== -1 && (url.indexOf("/ads") !== -1 || url.indexOf("/doubleclick") !== -1)) {
        return "PROXY 0.0.0.0:0";
    }

    // General ad-blocking based on regex
    if (adRegex.test(host)) {
        return "PROXY 0.0.0.0:0";
    }

    // Default action: direct connection
    return "DIRECT";
}
