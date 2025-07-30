/*
 * Pdm WebExtension (forked from uget-chrome-wrapper ) is an extension to integrate Persepolis Download manager
 * with Google Chrome, Chromium, Firefox and Vivaldi in Linux, Windows and OSX.
 *
 * Modified copyright (C) 2017  Jafar Akhondali
 * Copyright (C) 2016  Gobinath
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


const DEBUG = true;
const VERSION = "4.0.0"; // TODO: Does it work?
// const hostName = getNativeHostName();
const browserEnv = getBrowserApi();
const BrowserNameSpace = browserEnv.BrowserNameSpace;


// Only set up config (icons, context menu) on install/startup, not native connection
async function ensureExtensionConfigOnStartup() {
    try {
        await setConfig();
    } catch(e) {
        console.error("Error during extension config setup (startup):", e);
    }
}

BrowserNameSpace.runtime.onInstalled.addListener(ensureExtensionConfigOnStartup);
if (BrowserNameSpace.runtime.onStartup) {
    BrowserNameSpace.runtime.onStartup.addListener(ensureExtensionConfigOnStartup);
}


function detectBrowser() {
    const ua = navigator.userAgent;
    if (ua.includes("Edge")) return "edge";
    if (navigator.brave && typeof navigator.brave.isBrave === "function") return "brave";
    if (ua.includes("Vivaldi")) return "vivaldi";
    if (ua.includes("Opera") || ua.includes("OPR")) return "opera";
    if (ua.includes("Chromium")) return "chromium";
    if (ua.includes("Firefox")) return "firefox";
    if (ua.includes("Chrome")) return "chrome";
    return "unknown";
}

// Test native connection with handshake and timeout
function testNativeConnection(host, isStartup = false) {
    console.log(`[PDM] testNativeConnection (handshake) called for host: ${host}`);
    return new Promise((resolve, reject) => {
        let port;
        try {
            port = chrome.runtime.connectNative(host);
        } catch (e) {
            return reject(`Unable to connect to host ${host}: ${e.message}`);
        }

        let isDone = false;
        const timeout = setTimeout(() => {
            if (!isDone) {
                isDone = true;
                console.warn(`[PDM] testNativeConnection: handshake timeout for host: ${host}, disconnecting port`);
                try { port.disconnect(); } catch (_) {}
                reject("Handshake timeout");
            }
        }, 3000); // 3s timeout

        port.onMessage.addListener((msg) => {
            if (isDone) return;
            isDone = true;
            clearTimeout(timeout);
            console.log(`[PDM] testNativeConnection: received message from host ${host}:`, msg);
            try { port.disconnect(); } catch (_) {}
            resolve(msg);
        });

        port.onDisconnect.addListener(() => {
            if (!isDone) {
                isDone = true;
                clearTimeout(timeout);
                const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : "Disconnected before handshake";
                console.warn(`[PDM] testNativeConnection: failed for host ${host}. Error: ${err}`);
                reject(err);
            }
        });

        // send handshake request
        try {
            port.postMessage({ action: "handshake", version: "4.0.0" });
        } catch (e) {
            if (!isDone) {
                isDone = true;
                clearTimeout(timeout);
                reject(`Handshake send failed: ${e.message}`);
            }
        }
    });
}
// Robust async LibreWolf detection
async function detectLibreWolf() {
    let isLibreWolf = navigator.userAgent.toLowerCase().includes("librewolf");
    try {
        if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.getBrowserInfo) {
            const info = await browser.runtime.getBrowserInfo();
            if (info.name && info.name.toLowerCase().includes("librewolf")) isLibreWolf = true;
        }
    } catch (e) {}
    return isLibreWolf;
}

// Initialize native connection with fallback between hosts
async function initializeNativeConnection() {
    console.log("[PDM] initializeNativeConnection called");

    // Detect browser and build candidate hosts
    let browser = detectBrowser();
    let browserHost = `com.persepolis.${browser}`;
    const fallbackHost = `com.persepolis.pdmchromewrapper`;

    // Log detected browser
    console.log(`[PDM][BROWSER DETECT] Browser detected by detectBrowser(): ${browser}`);

    // Special handling for LibreWolf
    if (await detectLibreWolf()) {
        browser = 'librewolf';
        browserHost = 'com.persepolis.librewolf';
        console.log('[PDM][BROWSER DETECT] LibreWolf detected, using host:', browserHost);
    } else {
        console.log(`[PDM][BROWSER DETECT] Final browser used: ${browser}`);
    }

    const candidateHosts = [
        browserHost,
        fallbackHost
    ];

    for (const host of candidateHosts) {
        try {
            console.log(`[PDM] [FALLBACK LOG] Trying host (handshake): ${host}`);
            const response = await testNativeConnection(host);

            // If the response is valid and enable=true, save host
            if (response?.enable) {
                console.log(`[PDM] Native connection established with ${host}`);
                await chrome.storage.local.set({ savedHostName: host });
                console.log(`[PDM][HOST] Host selected and saved: ${host}`);
                return host; // Return immediately after success
            }
        } catch (err) {
            console.warn(`[PDM] [FALLBACK LOG] Host handshake failed (${host}). Error: ${err?.message}`);
        }
    }

    // If all attempts fail
    throw new Error("Failed to initialize native connection: No available native host.");
}




function getBrowserApi(){
    let isChrome=false,isFF=false, isVivaldi=false;

    // isSafari
    let BrowserNameSpace;
    if(typeof browser !== 'undefined' ){
        BrowserNameSpace = browser;
        isFF=true;
    }
    else if(typeof chrome !== 'undefined' ){
        BrowserNameSpace = chrome;
        isChrome=true;
        if(navigator.userAgent.includes('Vivaldi/'))
            isVivaldi = true; // Vivaldi is a subbrowser of chrome :|
    }

    return {
        BrowserNameSpace,
        isFF,
        isVivaldi,
        isChrome,
    };
}



function UrlMessage() {
    this.url= '';
    this.cookies= '';
    this.useragent= navigator.userAgent;
    this.referrer= '';
    this.postdata= '';
}

function arrayUnique(array) {
    var a = array.concat();
    for(var i=0; i<a.length; ++i) {
        for(var j=i+1; j<a.length; ++j) {
            if(a[i] === a[j])
                a.splice(j--, 1);
        }
    }
    return a;
}

//if str was encoded, return it. otherwise return encoded str
function denCode(str){
    //return encodeURIComponent(decodeURIComponent(str));
    return decodeURIComponent(str) !== str ? str : encodeURI(str);
}


function L(msg) {
    console.log(msg);
}



function getDomain(url){

    var TLDs = ["ac", "ad", "ae", "aero", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "arpa", "as", "asia", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "biz", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cat", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "com", "coop", "cr", "cu", "cv", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "edu", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gov", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "info", "int", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jobs", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mil", "mk", "ml", "mm", "mn", "mo", "mobi", "mp", "mq", "mr", "ms", "mt", "mu", "museum", "mv", "mw", "mx", "my", "mz", "na", "name", "nc", "ne", "net", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "org", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "pro", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "st", "su", "sv", "sy", "sz", "tc", "td", "tel", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tp", "tr", "travel", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xn--0zwm56d", "xn--11b5bs3a9aj6g", "xn--3e0b707e", "xn--45brj9c", "xn--80akhbyknj4f", "xn--90a3ac", "xn--9t4b11yi5a", "xn--clchc0ea0b2g2a9gcd", "xn--deba0ad", "xn--fiqs8s", "xn--fiqz9s", "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--g6w251d", "xn--gecrj9c", "xn--h2brj9c", "xn--hgbk6aj7f53bba", "xn--hlcj6aya9esc7a", "xn--j6w193g", "xn--jxalpdlp", "xn--kgbechtv", "xn--kprw13d", "xn--kpry57d", "xn--lgbbat1ad8j", "xn--mgbaam7a8h", "xn--mgbayh7gpa", "xn--mgbbh1a71e", "xn--mgbc0a9azcg", "xn--mgberp4a5d4ar", "xn--o3cw4h", "xn--ogbpf8fl", "xn--p1ai", "xn--pgbs0dh", "xn--s9brj9c", "xn--wgbh1c", "xn--wgbl6a", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--yfro4i67o", "xn--ygbi2ammx", "xn--zckzah", "xxx", "ye", "yt", "za", "zm", "zw"].join()

    url = url.replace(/.*?:\/\//g, "");
    url = url.replace(/www./g, "");
    var parts = url.split('/');
    url = parts[0];
    var parts = url.split('.');
    if (parts[0] === 'www' && parts[1] !== 'com'){
        parts.shift()
    }
    var ln = parts.length
        , i = ln
        , minLength = parts[parts.length-1].length
        , part;

    // iterate backwards
    while(part = parts[--i]){
        // stop when we find a non-TLD part
        if (i === 0                    // 'asia.com' (last remaining must be the SLD)
            || i < ln-2                // TLDs only span 2 levels
            || part.length < minLength // 'www.cn.com' (valid TLD as second-level domain)
            || TLDs.indexOf(part) < 0  // officialy not a TLD
        ){
            var actual_domain = part;
            break;
            //return part
        }
    }
    //console.log(actual_domain);
    var tid ;
    if(typeof parts[ln-1] != 'undefined' && TLDs.indexOf(parts[ln-1]) >= 0)
    {
        tid = '.'+parts[ln-1];
    }
    if(typeof parts[ln-2] != 'undefined' && TLDs.indexOf(parts[ln-2]) >= 0)
    {
        tid = '.'+parts[ln-2]+tid;
    }
    if(typeof tid != 'undefined')
        actual_domain = actual_domain+tid;
    else
        actual_domain = actual_domain+'.com';


    return actual_domain;
}


function getCookies(url,callback) {
    let domain = getDomain(url);// This function was one of the best functions i've ever seen, but now it's useless. I'll not delete it because i love it... I want to spread it to world using persepolis ... RIP my friend
    //let domainQuery= {domain:domain};
    let urlQuery = {url:url};

    let blacklistDecode = [
        "mycdn.me"
    ];
    if (browserEnv.isChrome) {
        BrowserNameSpace.cookies.getAll(urlQuery,(urlcookies)=>{
            let cookieArray = [];
            if (blacklistDecode.indexOf(domain)  == -1)
                cookieArray = urlcookies.map((cookie)=>denCode(cookie.name)+ "=" + denCode(cookie.value));
            else
                cookieArray = urlcookies.map((cookie)=>cookie.name+ "=" + cookie.value);
            callback(cookieArray);
        });
    } else if (browserEnv.isFF) {
        BrowserNameSpace.cookies.getAll(urlQuery).then((urlcookies)=>{
            let cookieArray = [];
            if (blacklistDecode.indexOf(domain)  == -1)
                cookieArray = urlcookies.map((cookie)=>{return denCode(cookie.name)+ "=" + denCode(cookie.value);});
            else
                cookieArray = urlcookies.map((cookie)=>{return cookie.name+ "=" + cookie.value});
            L(cookieArray);
            callback(cookieArray);
        });
    }
}


function setCookies(message) {
    return new Promise(function(ok, fuck) {
        message.useragent = navigator.userAgent;
        try{
            getCookies(message.url, urlCookie=> {
                if (!urlCookie || urlCookie.length === 0) {
                    console.warn("No cookies found for URL:", message.url);
                }
                message.cookies = arrayUnique(urlCookie).join("; ");
            });
        }catch (errors){
            L("Cookies are failed to load");
            L(errors);
            // fuck(errors); // :) Ignore cookie errors ( for cases that users disabled cookie access for extensions.
        }finally {
            ok(message);
        }
    });
}

function getFileNameFromUrl(link) {
    return link.split('/').pop().split('#')[0].split('?')[0];
}


//Send cookie and send data to SendToPDM function
function setCookieAndSendToPDM(message) {
    setCookies(message).then((cookie_with_message) => {
        L("Cookies set...");
        SendToPDM(cookie_with_message);
    });
}


function SendToPDM(data,callback){
    SendCustomMessage({
        url_links:data.constructor === Array ? data : [data],
        version: VERSION
    })
}


// Make sure hostName is accessible or retrieved where needed
//Crafter for sending message to PDM
async function SendCustomMessage(message) {
    try {
        // First try to get the saved host name from storage
        const result = await chrome.storage.local.get("savedHostName");
        console.log("[PDM][DEBUG] chrome.storage.local.get('savedHostName') returned:", result);
        let hostName = result && result.savedHostName;

        if (!hostName) {
            console.warn("[PDM] No savedHostName found. Re-initializing native connection...");
            hostName = await initializeNativeConnection();
        }

        if (!hostName) {
            throw new Error("Failed to determine native host name after initialization attempt.");
        }

        console.log(`[PDM] Sending custom message to host: ${hostName}`);
        console.log(`[PDM][HOST] Using native host: ${hostName}`);

        //  Open connection to the correct host
        const port = chrome.runtime.connectNative(hostName);
        port.postMessage(message);

        return new Promise((resolve, reject) => {
            let responded = false;

            port.onMessage.addListener((response) => {
                responded = true;
                console.log(`[PDM] Received response from ${hostName}:`, response);
                resolve(response);
                port.disconnect();
            });

            port.onDisconnect.addListener(() => {
                if (!responded) {
                    const errorMsg = chrome.runtime.lastError?.message || "Disconnected before response";
                    console.error(`[PDM] Native host ${hostName} disconnected: ${errorMsg}`);
                    reject(new Error(errorMsg));
                }
            });
        });

    } catch (err) {
        console.error("Failed to send custom message:", err);
        throw err;
    }
}



async function updateKeywords(data) {
    const keywords = data.toLowerCase()
        .split(/[\s,]+/)
        .filter(keyword => keyword.trim() !== "");
    await chromeStorageSetter('keywords', keywords.join());
}

async function isBlackListed(url) {
    /*if (url.includes("//docs.google.com/") || url.includes("googleusercontent.com/docs")) { // Cannot download from Google Docs
     return true;
     }*/
    if (url.startsWith("blob://")) // TODO: Persepolis currently can't handle blob type
        return true;
    const keywords = (await ConfigGetVal('keywords', ''))
        .split(/[\s,]+/)
        .filter(keyword => keyword.trim() !== "")

    return keywords.some(keyword => url.includes(keyword));
}

async function setInterruptDownload(interrupt) {
    L("Interrupts:" + interrupt);
    await chromeStorageSetter('pdmInterrupt', interrupt);
    // Use .action if available, else fallback to .browserAction (for MV2/Firefox/LibreWolf)
    const setIcon = (BrowserNameSpace.action && BrowserNameSpace.action.setIcon) ? BrowserNameSpace.action.setIcon : (BrowserNameSpace.browserAction && BrowserNameSpace.browserAction.setIcon ? BrowserNameSpace.browserAction.setIcon : null);
    if (setIcon) {
        if (interrupt) {
            setIcon({path: "./icons/icon_32.png"});
        } else {
            setIcon({path: "./icons/icon_disabled_32.png"});
        }
    }
}



async function getExtensionConfig() {
    return {
        'pdmInterrupt': await ConfigGetVal('pdmInterrupt'),
        'contextMenu':  await ConfigGetVal('contextMenu'),
        'keywords': await ConfigGetVal('keywords', '')
    }
}

async function chromeStorageGetter(key) {
    return new Promise(resolve => {
        chrome.storage.local.get(key, (obj)=> {
            return resolve(obj[key] || '');
        })
    });
}

async function chromeStorageSetter(key, value) {
    return new Promise(resolve => {
        chrome.storage.local.set({[key]: value}, resolve);
    });
}

async function ConfigGetVal(key, default_value='') {
    let configValue = default_value;
    try {
        configValue = await chromeStorageGetter(key);
    } catch (e) {
        console.error('[PDM] Error getting key from storage:', key, e);
    }
    if (key === 'savedHostName') {
        console.log('[PDM] ConfigGetVal for savedHostName:', configValue);
    }
    L("Getting Key:" + key + " ::  " + configValue)
    if (["true", "false"].includes(configValue))
        return configValue == "true"; // Converts string Boolean to Boolean
    return configValue;
}


async function setContextMenu(newState) {
    if (!newState) {
        BrowserNameSpace.contextMenus.removeAll();
        return
    }
    try {
        //Add download with persepolis to context menu
        BrowserNameSpace.contextMenus.create({
                title: 'Download with Persepolis',
                id: "download_with_pdm",
                contexts: ['link']
            }
            , () => void chrome.runtime.lastError
        );

        //Add download selected text to context menu
        BrowserNameSpace.contextMenus.create({
                title: 'Download Selected links with Persepolis',
                id: "download_links_with_pdm",
                contexts: ['selection']
            }
            , () => void chrome.runtime.lastError
        );

        //Add download ALL LINKS to context menu
        BrowserNameSpace.contextMenus.create({
                title: 'Download All Links with Persepolis',
                id: "download_all_links_with_pdm",
                contexts: ['page']
            }
            , () => void chrome.runtime.lastError);
    } catch (e) {
        //Who cares?
    }

    await chromeStorageSetter('contextMenu', newState);
}


async function setConfig() {
    //TODO: This function should be removed I think, at least global part
    let {
        pdmInterrupt,
        contextMenu,
        keywords,
    } = await getExtensionConfig();

    await setInterruptDownload(pdmInterrupt);

    await setContextMenu(contextMenu);
}



/**
 * @param {Object} params
 * @param {boolean} params.pdmInterrupt
 * @param {boolean} params.contextMenu
 * @param {string} params.keywords
 */
async function setExtensionConfig({ pdmInterrupt, contextMenu, keywords }) {

    if (pdmInterrupt !== undefined) await setInterruptDownload(pdmInterrupt);
    if (keywords !== undefined) await chromeStorageSetter('keywords', keywords);
    if (contextMenu !== undefined) {
        await chromeStorageSetter('contextMenu', contextMenu);
        setContextMenu(contextMenu)
    }
}




BrowserNameSpace.runtime.onMessage.addListener((request, sender, sendResponse) => {
    L("Inside runtime on message")

    if (["getAll", "getSelected"].includes(request.type)) {

        let links = request.message;

        L("enterted " + request.type);

        let promiseQueue = [];
        for (let link of links) {
            //Check if we already didnt send this link
            if (link !== "") {
                let msg = new UrlMessage();
                msg.url = link;
                msg.referrer = sender.url;
                promiseQueue.push(setCookies(msg));
            }
        }
        Promise.all(promiseQueue).then(allPromises => {
            SendToPDM(allPromises);
        }, function (err) {
            L("Some error :) " + err)
        });
        return
    }

    switch (request.type) {
        case "keyPress": {
            // https://stackoverflow.com/questions/44056271/chrome-runtime-onmessage-response-with-async-await
            // TODO Has issues? interrupt doesn't get reset sometimes
            (async () => {
                let interruptDownloads = !!(await chromeStorageGetter('pdmInterrupt'));

                let msg = request.message;
                if (msg === 'enable') {
                    // Temporarily enable
                    setInterruptDownload(true);
                } else if (msg === 'disable') {
                    // Temporarily disable
                    setInterruptDownload(false);
                } else {
                    // Toggle
                    setInterruptDownload(!interruptDownloads);
                }
            })();
            break
        }

        case "getExtensionConfig": {
            getExtensionConfig().then(sendResponse)
            return true;
        }

        case "setExtensionConfig": {
            setExtensionConfig({...request.data})
            break
        }

    }

});


BrowserNameSpace.contextMenus.onClicked.addListener(function (info, tab) {
    "use strict";
    switch (info.menuItemId) {
        case "download_with_pdm":
            L(info['linkUrl']);
            let msg = new UrlMessage();
            msg.url = info['linkUrl'];
            msg.referrer = info['pageUrl'];
            setCookieAndSendToPDM(msg);
            break;

        case "download_links_with_pdm":
            BrowserNameSpace.scripting.executeScript({
                target: { tabId: tab.id },
                files: ["/scripts/injector.js"]
            }, () => {
                BrowserNameSpace.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ["/scripts/getselected.js"]
                });
            });
            break;


        case "download_all_links_with_pdm":
            BrowserNameSpace.scripting.executeScript({
                target: { tabId: tab.id },
                files: ["/scripts/injector.js"]
            }, () => {
                BrowserNameSpace.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ["/scripts/getall.js"]
                });
            })
    }
});

// This api is called before onCreated
// So maybe a flag and use existing method??
// Firefox interrupt has issues and 
//https://github.com/ugetdm/uget-integrator/issues/108

//Finding files types in chrome is not like firefox
//Cause firefox first find file type then start download but chrome uses another event
//Vivaldi uses Chrome engine, But saves files like firefox :|

// Robust detection for all major browsers, including Brave using navigator.brave.isBrave()
(async () => {
    const ua = navigator.userAgent.toLowerCase();
    const isLibreWolf = ua.includes('librewolf');
    const isFF = browserEnv.isFF || ua.includes('firefox');
    const isVivaldi = browserEnv.isVivaldi || ua.includes('vivaldi');
    const isOpera = ua.includes('opr') || ua.includes('opera');
    const isChromium = ua.includes('chromium') && !isVivaldi && !isOpera;
    let isBrave = false;
    if (navigator.brave && typeof navigator.brave.isBrave === 'function') {
        try {
            isBrave = await navigator.brave.isBrave();
        } catch (e) {
            isBrave = false;
        }
    }
    const isChrome = browserEnv.isChrome && ua.includes('chrome') && !isVivaldi && !isChromium && !isBrave && !isOpera;

   
    if (isFF && BrowserNameSpace.downloads.onDeterminingFilename) {
        // Prefer onDeterminingFilename for Firefox if available
        BrowserNameSpace.downloads.onDeterminingFilename.addListener(handleDownloadIterrupts);
    } else if ((isLibreWolf || isFF) && BrowserNameSpace.downloads.onCreated) {
        // Fallback for Firefox/LibreWolf if onDeterminingFilename is not available
        BrowserNameSpace.downloads.onCreated.addListener((downloadItem) => handleDownloadIterrupts(downloadItem, null));
    } else if ((isChrome || isVivaldi || isOpera || isChromium || isBrave) && BrowserNameSpace.downloads.onCreated) {
        // All Chromium-based browsers
        BrowserNameSpace.downloads.onCreated.addListener((downloadItem) => handleDownloadIterrupts(downloadItem, null));
    }
})();

/**
 *
 * @param {object} downloadItem
 * @param {function | undefined} suggest
 */
async function handleDownloadIterrupts(downloadItem, suggest) {
    console.log('[PDM][DEBUG] handleDownloadIterrupts FIRED:', downloadItem);
    const { BrowserNameSpace } = getBrowserApi();
    let { pdmInterrupt } = await getExtensionConfig();
    console.log('[PDM] handleDownloadIterrupts called:', downloadItem);
    if (!pdmInterrupt) {
        console.log('[PDM] pdmInterrupt is false, not capturing.');
        if (typeof suggest === 'function') suggest();
        return;
    }

    let url = downloadItem['finalUrl'] || downloadItem['url'];
    if (!url) {
        console.log('[PDM] No URL found in downloadItem.');
        if (typeof suggest === 'function') suggest();
        return;
    }
    if (await isBlackListed(url)) {
        console.log('[PDM] URL is blacklisted:', url);
        if (typeof suggest === 'function') suggest();
        return;
    }

    let fileName = downloadItem['filename'] || '';
    const MIN_FILE_SIZE_INTERRUPT = 5 * (1024 * 1024); // Don't interrupt downloads less than 5 MB
    let extension = fileName.split('.').pop();

    if (
        (fileName !== '' && await isBlackListed(extension)) ||
        (0 < downloadItem.fileSize && downloadItem.fileSize < MIN_FILE_SIZE_INTERRUPT)
    ) {
        console.log('[PDM] File extension or size is blacklisted/skipped:', extension, downloadItem.fileSize);
        if (typeof suggest === 'function') suggest();
        return;
    }

    // Log file size for debug
    setTimeout(() => {
        console.log('[PDM] File size (delayed):', downloadItem.fileSize);
    }, 2000);

    try {
        await BrowserNameSpace.downloads.cancel(downloadItem.id); // Cancel the download
        await BrowserNameSpace.downloads.erase({ id: downloadItem.id }); // Erase the download from list
        console.log('[PDM] Download canceled and erased:', downloadItem.id);
    } catch (e) {
        console.warn('[PDM] Error canceling/erasing download:', e);
    }

    let msg = new UrlMessage();
    msg.url = url;
    msg.referrer = downloadItem['referrer'] || '';
    setCookieAndSendToPDM(msg);

    // Do NOT call suggest() after canceling, as we want to fully intercept
}
