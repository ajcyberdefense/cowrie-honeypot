# Part 1: Oracle Cloud Setup (Always Free)

Provision the honeypot host on Oracle Cloud Infrastructure's Always Free tier — a permanently free VM with a public IPv4 address, which is what a honeypot needs and what most free tiers do not give you.

> Deploying on AWS instead? Use [01-aws-setup.md](01-aws-setup.md). Everything from [Part 2](02-hardening.md) onward is identical.

---

## Why Oracle for this

| | Oracle Always Free | AWS Free Tier |
|---|---|---|
| Duration | Permanent | 12 months, then billed |
| Public IPv4 | Included | Included (Elastic IP) |
| Cost after trial | $0 | ~$8–10/mo |

The catch is capacity and idle reclamation, both covered below.

---

## Step 1: Create the Account

1. Sign up at [cloud.oracle.com](https://cloud.oracle.com)
2. You need a card for identity verification — it is **not** charged while you stay on Always Free resources
3. Pick your **home region** carefully. It cannot be changed later, and Always Free capacity varies by region. Choose one geographically near you that is not a heavily-subscribed metro

After signup you get a 30-day trial with credits. When it expires the account downgrades to Always Free and your Always Free resources keep running.

---

## Step 2: Choose a Shape

Oracle offers two Always Free compute shapes. They are very different.

| Shape | CPU | RAM | Availability | Verdict for Cowrie |
|---|---|---|---|---|
| **VM.Standard.E2.1.Micro** | 1 OCPU (x86) | 1 GB | Almost always available | **Recommended** |
| VM.Standard.A1.Flex | up to 4 OCPU (ARM) | up to 24 GB | Frequently "out of capacity" | Overkill |

Cowrie idles at roughly 80–150 MB of RAM. The 1 GB micro shape is genuinely sufficient, and you avoid fighting for ARM capacity.

> **If you want the ARM shape anyway:** expect `Out of host capacity` errors. People retry for days. Cowrie does run fine on ARM — `pip install cowrie` pulls `aarch64` wheels — but it buys you nothing here.

---

## Step 3: Launch the Instance

**Compute → Instances → Create Instance**

| Setting | Value |
|---|---|
| **Name** | `cowrie-honeypot` |
| **Image** | Canonical Ubuntu 22.04 |
| **Shape** | `VM.Standard.E2.1.Micro` |
| **VCN** | Create new (accept defaults) |
| **Subnet** | Public subnet |
| **Assign public IPv4** | **Yes** — critical, the honeypot is unreachable without it |

### SSH Keys

Generate a keypair locally and paste the **public** key:

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\cowrie_oracle -C "cowrie-honeypot"
Get-Content $env:USERPROFILE\.ssh\cowrie_oracle.pub
```

Paste the `.pub` contents into **Add SSH keys → Paste public keys**.

> Keep the private key (`cowrie_oracle`, no extension). Oracle cannot recover it, and password auth is disabled in Part 2.

Click **Create**. The instance is running in about a minute.

> **Ubuntu images on OCI use the `ubuntu` login user**, not `opc`. (`opc` is for Oracle Linux images.)

---

## Step 4: Reserve the Public IP

By default the public IP is **ephemeral** — it changes if the instance is stopped and started. Promote it so it is stable:

1. **Instance → Resources → Attached VNICs →** click the VNIC
2. **IPv4 Addresses →** edit the public IP entry
3. Change **Ephemeral** to **Reserved**, give it a name, save

Confirm the free-tier allowance for reserved IPs in your tenancy before relying on it; the ephemeral IP works fine for testing either way.

---

## Step 5: Open Ingress Ports

This is Oracle's cloud firewall, separate from the host firewall you configure in Part 2. **Both must allow the traffic.**

**Networking → Virtual Cloud Networks →** your VCN **→ Security Lists →** Default Security List **→ Add Ingress Rules**

| Source CIDR | Protocol | Dest. Port | Purpose |
|---|---|---|---|
| `0.0.0.0/0` | TCP | `22` | Cowrie fake SSH — the bait |
| `0.0.0.0/0` | TCP | `23` | Cowrie fake Telnet — the bait |
| `<your-ip>/32` | TCP | `2223` | **Real admin SSH** |
| `<your-ip>/32` | TCP | `80` | Dashboard (Part 4) |

Leave **Stateful** checked on all of them.

> **Add the `2223` rule before you run `harden.sh`.** That script moves your real SSH to 2223; if the cloud firewall has not been opened first, you lock yourself out the moment the session drops.

Find your own IP at [whatismyip.com](https://whatismyip.com). On a residential connection it changes periodically — if admin SSH stops working later, re-check this rule first.

---

## Step 6: First Login

Port 22 still reaches the real sshd at this point. Cowrie takes it over in Part 2.

```powershell
ssh -i $env:USERPROFILE\.ssh\cowrie_oracle ubuntu@YOUR_PUBLIC_IP
```

Type `yes` at the fingerprint prompt.

---

## Step 7: Add Swap (1 GB shapes only)

With 1 GB of RAM, compiling any Python wheel that lacks a prebuilt binary can hit OOM. A 2 GB swap file removes the risk:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
free -h
```

Skip this on the A1.Flex shape.

---

## The Two Oracle Gotchas

### 1. Preinstalled iptables rules

Oracle's Ubuntu images ship with their **own restrictive iptables ruleset** persisted at `/etc/iptables/rules.v4`. It permits port 22 and rejects nearly everything else — and **UFW does not manage it**.

The symptom is maddening: the Security List allows 2222, UFW says `ALLOW`, and connections still hang.

```bash
sudo iptables -L INPUT -n --line-numbers   # look for REJECT rules
```

`harden.sh` detects this and offers to flush the rules so UFW owns filtering exclusively. Accept when prompted.

### 2. Idle instance reclamation

Oracle reclaims Always Free compute that looks idle (roughly: sustained low CPU, low network, low memory over a 7-day window). **A honeypot is exactly that shape of workload** — low CPU even under constant scanning.

Two mitigations:

- **Upgrade the account to Pay As You Go.** Always Free resources stay free, but they become exempt from idle reclamation. This is the reliable fix — no charge as long as you stay within Always Free limits.
- Or accept the risk and be ready to redeploy. The whole box is reproducible from these scripts in about 10 minutes.

---

## Setup Checklist

- [ ] Oracle account created, home region chosen
- [ ] `VM.Standard.E2.1.Micro` running Ubuntu 22.04
- [ ] Public IPv4 assigned (reserved if available)
- [ ] SSH keypair generated, private key stored safely
- [ ] Ingress: 22 + 23 from `0.0.0.0/0`
- [ ] Ingress: 2223 + 80 from **your IP only**
- [ ] Logged in over SSH as `ubuntu`
- [ ] Swap added (1 GB shape)

---

## Troubleshooting

**`Out of host capacity`**
The A1.Flex ARM shape is heavily oversubscribed. Switch to `VM.Standard.E2.1.Micro`, or retry in another availability domain.

**Connection times out on first login**
Check the instance has a public IP, the Security List has the port 22 ingress rule, and you are targeting the public (not private) address.

**`Permission denied (publickey)`**
Use the `ubuntu` user, not `opc` or `root`. Point `-i` at the private key, not the `.pub`.

**Everything was working, now admin SSH hangs**
Your home IP probably changed. Update the `2223` ingress rule.

---

Next: [Part 2: Instance Hardening](02-hardening.md)
