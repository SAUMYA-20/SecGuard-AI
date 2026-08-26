const mongoose = require('mongoose');
const { User } = require('../models/schema');

/**
 * Developer Pro: Free & open tier for all developers with unlimited scans and zero authentication required.
 */
async function getOrCreateUser(userId, tier = 'developer') {
  if (mongoose.connection.readyState !== 1) {
    return {
      _id: 'developer_pro_user',
      email: 'developer@secguard.ai',
      tier: 'developer',
      scansToday: 0,
      save: async () => {}
    };
  }

  if (userId && mongoose.Types.ObjectId.isValid(userId)) {
    const existing = await User.findById(userId);
    if (existing) return existing;
  }

  // Find or create default developer user
  let devUser = await User.findOne({ email: 'developer@secguard.ai' });
  if (!devUser) {
    devUser = await User.create({
      email: 'developer@secguard.ai',
      tier: 'developer',
      scansToday: 0,
      lastScanDate: new Date()
    });
  }
  return devUser;
}

/**
 * Developer Pro Rate Limiter: Unlimited scans pass-through with usage tracking.
 */
async function tierRateLimiter(req, res, next) {
  try {
    const user = await getOrCreateUser(req.body.userId || req.query.userId, 'developer');
    user.scansToday = (user.scansToday || 0) + 1;
    if (typeof user.save === 'function') {
      await user.save();
    }
    req.user = user;
    next();
  } catch (err) {
    console.warn('[rateLimiter] Notice:', err.message);
    next();
  }
}

module.exports = { tierRateLimiter, getOrCreateUser };
