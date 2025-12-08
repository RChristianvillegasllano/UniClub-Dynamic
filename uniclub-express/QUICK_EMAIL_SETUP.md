# Quick Email Setup for Forgot Password

## ⚠️ Current Status
Your email service is not configured. The forgot password feature requires email setup.

## 🚀 Quick Setup (Gmail - Recommended)

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account: https://myaccount.google.com
2. Navigate to **Security** → **2-Step Verification**
3. Enable 2-Step Verification if not already enabled

### Step 2: Generate App Password
1. Still in Security settings, scroll to **App passwords**
2. Select **Mail** as the app
3. Select **Other (Custom name)** as device
4. Enter "UniClub" as the name
5. Click **Generate**
6. **Copy the 16-character password** (you'll need this)

### Step 3: Add to .env File
Create or edit `.env` file in `uniclub-express` directory:

```env
# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-char-app-password-here
EMAIL_FROM="UniClub System <your-email@gmail.com>"
```

**Replace:**
- `your-email@gmail.com` with your Gmail address
- `your-16-char-app-password-here` with the app password from Step 2

### Step 4: Restart Server
After saving `.env`, restart your server:
```bash
npm start
# or
npm run dev
```

You should see: `✅ Email service ready`

## 📧 Alternative: Test Mode (Development Only)

If you want to test without real email, you can use Ethereal Email (test service):

1. Install: `npm install ethereal-email` (optional)
2. Or use a test SMTP service like Mailtrap

## ✅ Verification

Once configured, test the forgot password flow:
1. Go to `/officer/login`
2. Click "Forgot your password?"
3. Enter an officer username
4. Check the officer's `{studentid}@umindanao.edu.ph` email for OTP

## 🔍 Troubleshooting

**Error: "Missing credentials"**
- Check that `SMTP_USER` and `SMTP_PASS` are set in `.env`
- Restart server after updating `.env`

**Error: "Invalid login"**
- For Gmail: Make sure you're using an App Password, not your regular password
- Verify 2-Step Verification is enabled

**Email not sending**
- Check spam folder
- Verify email address format: `{studentid}@umindanao.edu.ph`
- Check server logs for detailed error messages

## 📚 Full Documentation
See `EMAIL_SETUP.md` for detailed configuration options and other email providers.




















