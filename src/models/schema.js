const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  tier: { type: String, enum: ['community', 'developer', 'enterprise'], default: 'community' },
  apiUsageCount: { type: Number, default: 0 },
  lastScanDate: { type: Date, default: null },
  scansToday: { type: Number, default: 0 }
}, { timestamps: true });

const AuditResultSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  url: { type: String, required: true },
  normalizedUrl: { type: String },
  timestamp: { type: Date, default: Date.now },
  securityScore: { type: Number, required: true },
  grade: { type: String },
  aiInsights: { type: String },
  deductions: [Object],
  headers: Object,
  ssl: Object,
  domAnalysis: Object,
  status: { type: String, enum: ['queued', 'processing', 'complete', 'failed'], default: 'queued' }
}, { timestamps: true });

// Index to make historical drift queries fast (per user, per url, sorted by time)
AuditResultSchema.index({ userId: 1, url: 1, timestamp: -1 });
AuditResultSchema.index({ url: 1, timestamp: -1 });
AuditResultSchema.index(
  { userId: 1, normalizedUrl: 1, timestamp: -1 },
  { partialFilterExpression: { normalizedUrl: { $exists: true } } }
);
AuditResultSchema.index({ userId: 1, timestamp: -1 });

module.exports = {
  User: mongoose.models.User || mongoose.model('User', UserSchema),
  AuditResult: mongoose.models.AuditResult || mongoose.model('AuditResult', AuditResultSchema)
};
