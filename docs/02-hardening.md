# Part 2: Instance Hardening

This guide covers hardening your fresh Ubuntu EC2 instance before deploying Cowrie. Run every command in order.

> **Prerequisites:** You are SSH'd into your instance on port 22 (temporary). See [Part 1](01-aws-setup.md).

---

## A: Update the System

Always update before anything else — patches fix known vulnerabilities.

```bash
sudo apt update && sudo apt upgrade -y
```

This takes 2–3 minutes. Let it complete fully.

---

## B: Move Real SSH to Port 2223

We move SSH off the default port 22 so attackers only find Cowrie's fake SSH.

```bash
sudo nano /etc/ssh/sshd_config
```

Find each line below and edit it (remove the `#` if present, and set the correct value):

```
Port 2223
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers ubuntu
```

> **Nano tips:**
> - `Ctrl + W` to search for text
> - Arrow keys to navigate
> - `Ctrl + X` → `Y` → `Enter` to save and exit

Apply the changes:

```bash
sudo systemctl restart sshd
```

### Verify Before Closing Your Session

**Open a second terminal** and confirm port 2223 works:

```bash
ssh -i ~/Downloads/your-key.pem -p 2223 ubuntu@YOUR_ELASTIC_IP
```

> **Do not close your original session until this succeeds.** If you lose access, you would need to use the AWS EC2 Instance Connect feature to recover.

Once confirmed working, go back to AWS and **remove the port 22 inbound rule** from your security group.

---

## C: Configure UFW Firewall

UFW (Uncomplicated Firewall) controls which ports are accessible on the server itself.

```bash
# Block all incoming connections by default
sudo ufw default deny incoming

# Allow all outgoing connections
sudo ufw default allow outgoing

# Allow your real admin SSH port
sudo ufw allow 2223/tcp

# Allow Cowrie's fake SSH port
sudo ufw allow 2222/tcp

# Allow Cowrie's fake Telnet port
sudo ufw allow 23/tcp

# Enable the firewall
sudo ufw enable
```

Type `y` when prompted. Verify the rules:

```bash
sudo ufw status
```

Expected output:
```
Status: active

To                         Action      From
--                         ------      ----
2223/tcp                   ALLOW       Anywhere
2222/tcp                   ALLOW       Anywhere
23/tcp                     ALLOW       Anywhere
```

---

## D: Lock the Root Account

```bash
sudo passwd -l root
```

No output = success. The root account is now locked.

---

## E: Install Fail2ban

Fail2ban monitors log files and automatically bans IPs that fail authentication too many times.

```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo systemctl status fail2ban
```

Look for `Active: active (running)` in the output.

---

## F: Create the Cowrie System User

Cowrie must never run as root. Create a dedicated low-privilege user:

```bash
sudo adduser --disabled-password --gecos "" cowrie
```

Verify it was created:

```bash
id cowrie
```

You should see output like: `uid=1001(cowrie) gid=1001(cowrie) groups=1001(cowrie)`

---

## G: Install Cowrie Dependencies

```bash
sudo apt install -y python3-pip python3-venv git \
  libssl-dev libffi-dev build-essential \
  libpython3-dev python3-minimal authbind \
  virtualenv
```

---

## Hardening Checklist

- [ ] System updated (`apt update && apt upgrade`)
- [ ] SSH moved to port 2223
- [ ] Can connect on port 2223 with key file
- [ ] Port 22 rule removed from AWS security group
- [ ] UFW active and showing correct ports
- [ ] Root account locked
- [ ] Fail2ban running
- [ ] `cowrie` user created
- [ ] Dependencies installed

---

## Troubleshooting

**Locked out after restarting SSH?**
Go to AWS Console → EC2 → Connect → use "EC2 Instance Connect" (browser-based terminal) to get back in without SSH.

**UFW blocked your connection?**
In EC2 Instance Connect, run `sudo ufw allow 2223/tcp` then try reconnecting.

**Fail2ban banning your own IP?**
```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip YOUR_IP
```

---

Next: [Part 3: Installing Cowrie](03-cowrie-install.md) *(coming soon)*
