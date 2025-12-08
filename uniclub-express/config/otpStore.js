// config/otpStore.js
// In-memory OTP storage (for production, consider using Redis or database)

const otpStore = new Map();

/**
 * Generate a 6-digit OTP
 * @returns {string}
 */
export function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Store OTP with expiration (10 minutes)
 * @param {string} identifier - Username or email
 * @param {string} otp - OTP code
 * @param {number} officerId - Officer ID
 * @returns {void}
 */
export function storeOTP(identifier, otp, officerId) {
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  otpStore.set(identifier.toLowerCase(), {
    otp,
    officerId,
    expiresAt,
    attempts: 0,
  });
  
  // Clean up expired OTPs
  setTimeout(() => {
    otpStore.delete(identifier.toLowerCase());
  }, 10 * 60 * 1000);
}

/**
 * Verify OTP
 * @param {string} identifier - Username or email
 * @param {string} otp - OTP code to verify
 * @returns {Object} { valid: boolean, officerId: number | null, error: string | null }
 */
export function verifyOTP(identifier, otp) {
  const key = identifier.toLowerCase();
  const stored = otpStore.get(key);
  
  if (!stored) {
    return { valid: false, officerId: null, error: 'OTP not found or expired' };
  }
  
  if (Date.now() > stored.expiresAt) {
    otpStore.delete(key);
    return { valid: false, officerId: null, error: 'OTP has expired' };
  }
  
  // Limit attempts to 5
  if (stored.attempts >= 5) {
    otpStore.delete(key);
    return { valid: false, officerId: null, error: 'Too many failed attempts. Please request a new OTP.' };
  }
  
  if (stored.otp !== otp) {
    stored.attempts += 1;
    return { valid: false, officerId: null, error: 'Invalid OTP code' };
  }
  
  // OTP is valid, return officer ID and remove from store
  const officerId = stored.officerId;
  otpStore.delete(key);
  return { valid: true, officerId, error: null };
}

/**
 * Get stored OTP info (for debugging)
 * @param {string} identifier - Username or email
 * @returns {Object | null}
 */
export function getOTPInfo(identifier) {
  return otpStore.get(identifier.toLowerCase()) || null;
}

/**
 * Clear all OTPs (for cleanup)
 */
export function clearAllOTPs() {
  otpStore.clear();
}




















