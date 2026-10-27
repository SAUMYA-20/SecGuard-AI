const mongoose = require('mongoose');
const { analyzeDOMContent } = require('./domAnalyzer');
const { analyzeHeadersAndTLS } = require('./headerAnalyzer');
const { generateAIEngineeredInsights } = require('./aiAgent');
const { calculateDeterministicScore, gradeFromScore } = require('./scoringEngine');
const { normalizeAuditUrl } = require('./auditUrl');
const { AuditResult } = require('../models/schema');

async function ensureDBConnection() {
  if (mongoose.connection.readyState === 1) return true;
  if (!process.env.MONGODB_URI) return false;
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    return true;
  } catch (err) {
    console.warn('[auditRunner] MongoDB connection warning:', err.message);
    return false;
  }
}

/**
 * Executes a full multi-vector security scan:
 * 1. Probes HTTP security headers & TLS cipher suite
 * 2. Parses DOM AST for inline scripts, obsolete jQuery, insecure form actions
 * 3. Evaluates deterministic mathematical score (0-100) and grade (A-F)
 * 4. Synthesizes executive analysis & Nginx/Apache configuration patches via Gemini AI
 * 5. Persists audit result and returns full structured telemetry
 */
async function executeAuditScan(url, userId = null) {
  let normalizedUrl = url.trim();
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  console.log(`[auditRunner] Starting security audit for: ${normalizedUrl}`);

  const [headerResult, domAnalysis] = await Promise.all([
    analyzeHeadersAndTLS(normalizedUrl),
    analyzeDOMContent(normalizedUrl)
  ]);

  const { score, deductions } = calculateDeterministicScore(headerResult, domAnalysis);
  const grade = gradeFromScore(score);

  const aiInsights = await generateAIEngineeredInsights({
    url: normalizedUrl,
    score,
    headers: headerResult,
    domAnalysis
  });

  const timestamp = new Date();
  const historyUrl = normalizeAuditUrl(normalizedUrl);
  let auditId = 'audit_' + Date.now();
  const dbConnected = await ensureDBConnection();

  if (dbConnected) {
    try {
      const validUserId = (userId && mongoose.Types.ObjectId.isValid(userId)) ? userId : null;
      const result = await AuditResult.create({
        userId: validUserId,
        url: normalizedUrl,
        normalizedUrl: historyUrl,
        timestamp,
        securityScore: score,
        grade,
        aiInsights,
        deductions,
        headers: headerResult,
        ssl: headerResult.tls,
        domAnalysis,
        status: 'complete'
      });
      auditId = result._id.toString();
      console.log(`[auditRunner] Scan persisted to MongoDB (${auditId}) for ${normalizedUrl}`);
    } catch (err) {
      console.warn('[auditRunner] Failed to persist scan to DB:', err.message);
    }
  }

  return {
    success: true,
    auditId,
    url: normalizedUrl,
    score,
    grade,
    deductions,
    aiInsights,
    headers: headerResult,
    ssl: headerResult.tls,
    domAnalysis,
    timestamp: timestamp.toISOString()
  };
}

module.exports = { executeAuditScan, ensureDBConnection };
