// config/email.js
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Check if email is configured
const hasEmailConfig = !!(process.env.SMTP_USER || process.env.EMAIL_USER) && 
                       !!(process.env.SMTP_PASS || process.env.EMAIL_PASSWORD);

let transporter = null;

if (hasEmailConfig) {
  // Create transporter for sending emails
  // For production, use SMTP settings (Gmail, SendGrid, etc.)
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER || process.env.EMAIL_USER,
      pass: process.env.SMTP_PASS || process.env.EMAIL_PASSWORD,
    },
  });

  // Verify transporter configuration
  transporter.verify((error, success) => {
    if (error) {
      console.log('❌ Email service configuration error:', error.message);
      console.log('⚠️  Forgot password feature will not work without proper email configuration');
      console.log('📧 Please check your SMTP settings in .env file');
    } else {
      console.log('✅ Email service ready');
    }
  });
} else {
  console.log('⚠️  Email service not configured');
  console.log('📧 Add SMTP credentials to .env file to enable forgot password feature');
  console.log('   Required: SMTP_USER, SMTP_PASS (or EMAIL_USER, EMAIL_PASSWORD)');
}

/**
 * Send OTP email to umindanao email address
 * @param {string} to - Recipient email (must be @umindanao.edu.ph)
 * @param {string} otp - 6-digit OTP code
 * @param {string} username - Officer username
 * @returns {Promise<Object>}
 */
export async function sendOTPEmail(to, otp, username) {
  // Check if email service is configured
  if (!transporter) {
    throw new Error('Email service is not configured. Please set up SMTP credentials in .env file.');
  }

  // Validate umindanao email
  if (!to || !to.endsWith('@umindanao.edu.ph')) {
    throw new Error('Email must be a valid umindanao.edu.ph address');
  }

  const mailOptions = {
    from: process.env.EMAIL_FROM || `"UniClub System" <${process.env.SMTP_USER}>`,
    to: to,
    subject: 'UniClub Officer Portal - Password Reset OTP',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .otp-box { background: white; border: 2px dashed #2563eb; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .otp-code { font-size: 32px; font-weight: bold; color: #2563eb; letter-spacing: 8px; font-family: 'Courier New', monospace; }
          .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; border-radius: 4px; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>UniClub Officer Portal</h1>
            <p>Password Reset Request</p>
          </div>
          <div class="content">
            <p>Hello <strong>${username}</strong>,</p>
            <p>You have requested to reset your password for your UniClub Officer Portal account.</p>
            <p>Please use the following One-Time Password (OTP) to verify your identity:</p>
            
            <div class="otp-box">
              <p style="margin: 0 0 10px 0; color: #6b7280; font-size: 14px;">Your OTP Code:</p>
              <div class="otp-code">${otp}</div>
            </div>
            
            <div class="warning">
              <strong>⚠️ Security Notice:</strong>
              <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                <li>This OTP is valid for <strong>10 minutes</strong> only</li>
                <li>Do not share this code with anyone</li>
                <li>If you did not request this, please ignore this email</li>
              </ul>
            </div>
            
            <p>Enter this code on the password reset page to continue.</p>
            <p>If you did not request a password reset, please contact your administrator immediately.</p>
          </div>
          <div class="footer">
            <p>This is an automated message from UniClub Management System</p>
            <p>&copy; ${new Date().getFullYear()} University of Mindanao. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
UniClub Officer Portal - Password Reset OTP

Hello ${username},

You have requested to reset your password for your UniClub Officer Portal account.

Your OTP Code: ${otp}

This OTP is valid for 10 minutes only.
Do not share this code with anyone.

If you did not request this, please ignore this email.

---
UniClub Management System
© ${new Date().getFullYear()} University of Mindanao
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ OTP email sent to:', to);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Error sending OTP email:', error);
    throw new Error('Failed to send OTP email. Please check email configuration.');
  }
}

export default transporter;

