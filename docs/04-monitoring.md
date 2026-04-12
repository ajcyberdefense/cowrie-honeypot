# Part 4: Monitoring & Web Dashboard

This guide sets up a real-time web dashboard to visualize Cowrie attack data in your browser.

---

## What the Dashboard Shows

- Total login attempts, unique attackers, sessions, commands, and downloads
- Bar charts of top attacking IPs and most-tried usernames
- Table of top passwords attackers use
- Table of commands attackers run after getting in
- Live feed of the last 20 login attempts
- Auto-refreshes every 30 seconds

---

## A: Open Port 80 in UFW

The dashboard runs on port 80 (standard web). Open it — but restrict to your IP only so the public can't see your attack data:

```bash
sudo ufw allow from YOUR_HOME_IP to any port 80
sudo ufw status
```

> Replace `YOUR_HOME_IP` with your actual IP. Find it at [whatismyip.com](https://whatismyip.com).

---

## B: Install Flask

Switch to the cowrie user:

```bash
sudo su - cowrie
cd cowrie
source cowrie-env/bin/activate
```

Install Flask:

```bash
pip install flask
```

---

## C: Copy the Dashboard Script

```bash
cp ~/cowrie/scripts/dashboard.py ~/cowrie/dashboard.py
```

---

## D: Test the Dashboard Manually

Run it to make sure it works:

```bash
sudo python3 ~/cowrie/dashboard.py
```

> We need `sudo` here because port 80 requires root privileges.

Open your browser and go to:
```
http://YOUR_ELASTIC_IP
```

You should see the dashboard. If you don't have much data yet, run the analyze.py script a few times or wait — real attackers will populate the logs within hours.

Press `Ctrl + C` to stop the test run.

---

## E: Run the Dashboard as a System Service

So the dashboard stays up permanently, run it via systemd.

Exit the cowrie user first:

```bash
exit
```

Install the service:

```bash
sudo cp /home/cowrie/cowrie/configs/dashboard.service /etc/systemd/system/dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable dashboard
sudo systemctl start dashboard
sudo systemctl status dashboard
```

Look for `Active: active (running)` in green.

---

## F: Verify Everything Is Running

```bash
sudo systemctl status cowrie
sudo systemctl status dashboard
```

Both should show `active (running)`.

Check open ports:

```bash
sudo ss -tlnp | grep -E '2222|23|80'
```

Expected output:
```
LISTEN  0  128  0.0.0.0:2222   cowrie (fake SSH)
LISTEN  0  128  0.0.0.0:23     cowrie (fake Telnet)
LISTEN  0  128  0.0.0.0:80     dashboard (web)
```

---

## G: View Live Logs

Watch attacks in real time:

```bash
sudo su - cowrie
cd cowrie
tail -f var/log/cowrie/cowrie.log
```

Filter for just login attempts:

```bash
tail -f var/log/cowrie/cowrie.log | grep "login attempt"
```

---

## H: Run the CLI Analyzer

For a terminal-based summary:

```bash
cd /home/cowrie/cowrie
source cowrie-env/bin/activate
python3 scripts/analyze.py
```

---

## Monitoring Checklist

- [ ] Port 80 open in UFW (restricted to your IP)
- [ ] Flask installed in cowrie virtualenv
- [ ] Dashboard accessible at `http://YOUR_ELASTIC_IP`
- [ ] Dashboard systemd service enabled and running
- [ ] Both `cowrie` and `dashboard` services show active
- [ ] Logs writing to `var/log/cowrie/cowrie.json`

---

## Tips

**Leave it running overnight.** Internet bots scan the entire IPv4 space for open SSH ports continuously. Within 24 hours you will see real login attempts from real attackers around the world.

**Common attacker passwords you'll see:** `123456`, `admin`, `password`, `root`, `1234`, `test`.

**Common attacker commands after getting in:**
- `uname -a` — checking OS version
- `cat /proc/cpuinfo` — checking CPU for crypto mining
- `wget http://...` — downloading malware
- `chmod +x ...` — making malware executable

These are all safely captured by Cowrie — none of them actually run on your real system.
