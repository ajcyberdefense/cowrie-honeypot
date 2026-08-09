# Part 1: AWS Instance Setup

This guide covers launching your EC2 instance, configuring security groups, and assigning a static Elastic IP.

---

## Step 1: Launch the EC2 Instance

1. Log into [AWS Console](https://console.aws.amazon.com)
2. Navigate to **EC2 → Launch Instance**
3. Configure the following:

| Setting | Value |
|---------|-------|
| **Name** | `cowrie-honeypot` |
| **AMI** | Ubuntu Server 22.04 LTS |
| **Instance type** | `t2.micro` (free tier) or `t3.small` |
| **Key pair** | Create new → ED25519 → Download `.pem` file |
| **Storage** | 20–30 GB gp3 |

> **Store your `.pem` key file safely — it cannot be recovered if lost.**

---

## Step 2: Configure Security Group Rules

Think of a Security Group as a firewall that controls who can reach your server and on which ports.

### Create the Security Group

1. Go to **EC2 → Security Groups → Create security group**
2. Fill in:
   - **Name:** `cowrie-honeypot-sg`
   - **Description:** `Security group for Cowrie honeypot`
   - **VPC:** Leave default

### Add Inbound Rules

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| `22` | TCP | **Anywhere (0.0.0.0/0)** | Cowrie fake SSH — redirected to 2222 |
| `23` | TCP | **Anywhere (0.0.0.0/0)** | Cowrie fake Telnet — redirected to 2323 |
| `2223` | TCP | **My IP** | Real admin SSH access |
| `80` | TCP | **My IP** | Dashboard (Part 4) |

> **Port 22 is exposed on purpose.** Attackers scan it constantly — that is exactly the traffic we want to capture. [Part 2](02-hardening.md) moves real SSH to 2223 and redirects `:22` to Cowrie on 2222, so nothing but the honeypot ever answers there.
>
> **Add the `2223` rule before running `harden.sh`**, or you will be locked out the moment your session drops.

### Outbound Rules
Leave outbound as default: **All traffic → Anywhere**

Click **Create security group**.

---

## Step 3: Assign an Elastic IP

An Elastic IP is a permanent public IP address. Without it, your server gets a new IP every time it restarts.

### Allocate

1. Go to **EC2 → Network & Security → Elastic IPs**
2. Click **Allocate Elastic IP address**
3. Leave all defaults → Click **Allocate**

### Associate

1. Check the box next to your new IP
2. Click **Actions → Associate Elastic IP address**
3. Select your EC2 instance from the dropdown
4. Select the private IP that appears
5. Click **Associate**

### Verify

Go to **EC2 → Instances**, click your instance. The **Public IPv4 address** in the details panel should now show your Elastic IP.

> **Cost note:** Elastic IPs are free while attached to a *running* instance. If you stop the instance, AWS charges ~$0.005/hr. Set a billing alert in AWS to avoid surprises.

---

## Connecting for the First Time

Port 22 still reaches the real sshd at this stage — Cowrie takes it over in Part 2.

1. Connect from your terminal:

**Mac/Linux:**
```bash
chmod 400 ~/Downloads/your-key.pem
ssh -i ~/Downloads/your-key.pem ubuntu@YOUR_ELASTIC_IP
```

**Windows (PowerShell):**
```powershell
ssh -i C:\Users\YourName\Downloads\your-key.pem ubuntu@YOUR_ELASTIC_IP
```

2. Type `yes` when prompted about the host fingerprint.

Once you're inside, proceed to [Part 2: Instance Hardening](02-hardening.md).

---

## AWS-Level Security Checklist

- [ ] Enable **MFA** on your AWS root account
- [ ] Create an **IAM user** with least-privilege for CLI work
- [ ] Enable **CloudTrail** for API audit logging
- [ ] Consider **AWS GuardDuty** for anomaly detection
- [ ] Set a **billing alert** to catch unexpected costs
