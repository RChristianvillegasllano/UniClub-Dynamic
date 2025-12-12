# SSH Key Setup Guide

This guide will help you generate and configure SSH keys for secure access to your Hostinger VPS.

---

## 🔑 Step 1: Generate SSH Key (Windows)

### Using PowerShell or Command Prompt

Open PowerShell or Command Prompt and run:

```bash
ssh-keygen -t ed25519 -C "rchristianllano@protonmail.com"
```

### What to Expect

You'll be prompted with several questions:

1. **"Enter file in which to save the key"**
   - **Default location:** `C:\Users\YourUsername\.ssh\id_ed25519`
   - **Press Enter** to use the default location, or specify a custom path

2. **"Enter passphrase (empty for no passphrase)"**
   - **Option A:** Press Enter twice for no passphrase (easier, less secure)
   - **Option B:** Enter a strong passphrase (more secure, required each time you use the key)
   - **Recommended:** Use a passphrase for better security

3. **"Enter same passphrase again"**
   - Re-enter your passphrase if you chose one

### Example Output

```
Generating public/private ed25519 key pair.
Enter file in which to save the key (C:\Users\YourUsername/.ssh/id_ed25519):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in C:\Users\YourUsername/.ssh/id_ed25519
Your public key has been saved in C:\Users\YourUsername/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx rchristianllano@protonmail.com
```

---

## 📋 Step 2: Locate Your SSH Keys

After generation, you'll have two files:

1. **Private Key:** `C:\Users\YourUsername\.ssh\id_ed25519`
   - ⚠️ **NEVER share this file** - Keep it secret!
   - This is your identity file

2. **Public Key:** `C:\Users\YourUsername\.ssh\id_ed25519.pub`
   - ✅ This is safe to share
   - This is what you'll add to your VPS

### View Your Public Key

**In PowerShell:**
```powershell
cat ~\.ssh\id_ed25519.pub
```

**Or in Command Prompt:**
```cmd
type %USERPROFILE%\.ssh\id_ed25519.pub
```

**Or open in Notepad:**
```powershell
notepad ~\.ssh\id_ed25519.pub
```

The public key will look something like:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx rchristianllano@protonmail.com
```

---

## 🚀 Step 3: Copy Public Key to Your VPS

### Method 1: Using ssh-copy-id (If Available)

**Note:** Windows doesn't have `ssh-copy-id` by default, but you can install it via Git Bash or use Method 2.

### Method 2: Manual Copy (Recommended for Windows)

1. **Copy your public key:**
   ```powershell
   # Display and copy the key
   cat ~\.ssh\id_ed25519.pub | clip
   ```
   This copies the key to your clipboard.

2. **Connect to your VPS:**
   ```bash
   ssh root@your-vps-ip-address
   # Or: ssh username@your-vps-ip-address
   ```

3. **On your VPS, create .ssh directory (if it doesn't exist):**
   ```bash
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   ```

4. **Add your public key to authorized_keys:**
   ```bash
   nano ~/.ssh/authorized_keys
   ```
   
   - Paste your public key (right-click to paste in terminal)
   - Press `Ctrl+X`, then `Y`, then `Enter` to save

5. **Set correct permissions:**
   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

### Method 3: One-Line Command (From Your Windows Machine)

**If you have OpenSSH client (Windows 10/11):**

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh root@your-vps-ip-address "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
```

Replace `your-vps-ip-address` with your actual VPS IP.

---

## ✅ Step 4: Test SSH Key Authentication

1. **Disconnect from your VPS** (if connected)

2. **Connect using your key:**
   ```bash
   ssh root@your-vps-ip-address
   # Or: ssh -i ~/.ssh/id_ed25519 root@your-vps-ip-address
   ```

3. **If you set a passphrase**, you'll be prompted to enter it

4. **You should connect without entering a password!**

---

## 🔒 Step 5: Disable Password Authentication (Optional but Recommended)

**⚠️ Only do this after confirming SSH key authentication works!**

1. **Connect to your VPS**

2. **Edit SSH configuration:**
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```

3. **Find and modify these lines:**
   ```bash
   # Change these:
   PasswordAuthentication yes
   PubkeyAuthentication yes
   
   # To:
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

4. **Save and exit** (`Ctrl+X`, `Y`, `Enter`)

5. **Restart SSH service:**
   ```bash
   sudo systemctl restart sshd
   # Or: sudo systemctl restart ssh
   ```

6. **Test connection again** (don't close your current session yet!)
   - Open a new terminal
   - Try connecting: `ssh root@your-vps-ip-address`
   - If it works, you're good!

---

## 🛠️ Troubleshooting

### "Permission denied (publickey)"

**Solution:**
1. Check file permissions on VPS:
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/authorized_keys
   ```

2. Verify your public key is in `authorized_keys`:
   ```bash
   cat ~/.ssh/authorized_keys
   ```

3. Check SSH server logs:
   ```bash
   sudo tail -f /var/log/auth.log
   # Or: sudo journalctl -u ssh -f
   ```

### "Could not open a connection to your authentication agent"

**Solution (Windows):**
```powershell
# Start SSH agent
Start-Service ssh-agent

# Add your key
ssh-add ~\.ssh\id_ed25519
```

### Key Not Found

**Solution:**
- Verify the key exists: `dir ~\.ssh\`
- Use full path: `ssh -i C:\Users\YourUsername\.ssh\id_ed25519 root@your-vps-ip`

### Wrong Permissions on VPS

**Solution:**
```bash
# Fix ownership
sudo chown -R $USER:$USER ~/.ssh

# Fix permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## 📝 Quick Reference

### Generate New Key
```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

### View Public Key
```powershell
cat ~\.ssh\id_ed25519.pub
```

### Copy Key to Clipboard (Windows)
```powershell
cat ~\.ssh\id_ed25519.pub | clip
```

### Connect with Specific Key
```bash
ssh -i ~/.ssh/id_ed25519 root@your-vps-ip
```

### Add Key to SSH Agent (Windows)
```powershell
Start-Service ssh-agent
ssh-add ~\.ssh\id_ed25519
```

---

## 🔐 Security Best Practices

1. ✅ **Use a passphrase** for your private key
2. ✅ **Never share your private key** (`id_ed25519`)
3. ✅ **Backup your private key** securely (encrypted USB, password manager)
4. ✅ **Use different keys** for different servers/services
5. ✅ **Disable password authentication** after setting up keys
6. ✅ **Keep your private key secure** - don't commit it to Git
7. ✅ **Rotate keys periodically** (every 6-12 months)

---

## 🎯 Next Steps

After setting up SSH keys:

1. ✅ Test key authentication works
2. ✅ Disable password authentication (optional)
3. ✅ Continue with VPS deployment (see `HOSTINGER_VPS_DEPLOYMENT.md`)
4. ✅ Set up additional security measures (fail2ban, firewall)

---

**Need Help?** If you encounter any issues, check the troubleshooting section or refer to the main deployment guide.

