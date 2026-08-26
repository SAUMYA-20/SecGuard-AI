const express = require('express');
const mongoose = require('mongoose');
const { dispatchAuditJob, getJobStatus } = require('../queue/auditQueue');
const { executeAuditScan } = require('../services/auditRunner');
const { tierRateLimiter, getOrCreateUser } = require('../middleware/rateLimiter');
const { AuditResult, User } = require('../models/schema');

const router = express.Router();

function normalizeUrl(rawUrl) {
  let url = (rawUrl || '').trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  return url;
}

// POST /api/audit — enqueue or dispatch a new asynchronous security scan
router.post('/audit', tierRateLimiter, async (req, res) => {
  const { url: rawUrl, userId, sync } = req.body;
  if (!rawUrl) {
    return res.status(400).json({ error: 'Target URL is required.' });
  }

  const url = normalizeUrl(rawUrl);

  try {
    new URL(url);
  } catch (err) {
    return res.status(400).json({ error: 'Target must be a valid URL (e.g. github.com or https://example.com)' });
  }

  const effectiveUserId = req.user ? req.user._id : userId;

  // Direct sync mode
  if (sync === true) {
    try {
      const result = await executeAuditScan(url, effectiveUserId);
      return res.json({
        message: 'Audit scan completed directly',
        state: 'completed',
        returnvalue: result,
        url,
        tier: 'developer'
      });
    } catch (directErr) {
      return res.status(500).json({ error: 'Direct audit scan failed', detail: directErr.message });
    }
  }

  try {
    const jobId = await dispatchAuditJob(url, effectiveUserId);
    res.status(202).json({
      message: 'Audit job dispatched successfully',
      jobId,
      url,
      tier: 'developer'
    });
  } catch (err) {
    console.error('[routes/audit] Dispatch failed:', err.message);
    res.status(500).json({ error: 'Failed to dispatch audit job', detail: err.message });
  }
});

// POST /api/audit/direct — direct synchronous execution
router.post('/audit/direct', tierRateLimiter, async (req, res) => {
  const { url: rawUrl, userId } = req.body;
  if (!rawUrl) return res.status(400).json({ error: 'Target URL is required.' });
  const url = normalizeUrl(rawUrl);
  try {
    const effectiveUserId = req.user ? req.user._id : userId;
    const result = await executeAuditScan(url, effectiveUserId);
    res.json({ success: true, returnvalue: result });
  } catch (err) {
    res.status(500).json({ error: 'Scan error', detail: err.message });
  }
});

// GET /api/audit/:jobId — poll BullMQ / in-memory job status
router.get('/audit/:jobId', async (req, res) => {
  const { jobId } = req.params;
  try {
    const status = await getJobStatus(jobId);
    if (!status) {
      return res.status(404).json({ error: 'Job not found', jobId });
    }
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get job status', detail: err.message });
  }
});

// GET /api/audit/result/:auditId — fetch full persisted audit document
router.get('/audit/result/:auditId', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database not connected' });
    }
    const result = await AuditResult.findById(req.params.auditId);
    if (!result) return res.status(404).json({ error: 'Audit result not found' });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve audit result', detail: err.message });
  }
});

// GET /api/audit/history — historical drift timeline
router.get('/audit/history/:userId?', async (req, res) => {
  try {
    const { userId } = req.params;
    const { url } = req.query;
    const filter = {};

    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      filter.userId = userId;
    }
    if (url) {
      filter.url = normalizeUrl(url);
    }

    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    const history = await AuditResult.find(filter)
      .sort({ timestamp: -1 })
      .limit(30)
      .select('url securityScore grade deductions timestamp status');

    res.json(history);
  } catch (err) {
    console.warn('[routes/audit] History lookup notice:', err.message);
    res.json([]);
  }
});

const { chatWithSecurityAgent } = require('../services/aiAgent');

// POST /api/audit/chat — interactive AI Security Copilot conversation
router.post('/audit/chat', async (req, res) => {
  try {
    const { message, auditContext, history } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message content is required.' });
    }

    const result = await chatWithSecurityAgent({
      userMessage: message,
      auditContext: auditContext || {},
      conversationHistory: history || []
    });

    res.json(result);
  } catch (err) {
    console.error('[routes/audit] AI Copilot chat error:', err.message);
    res.status(500).json({ error: 'AI Copilot inference failed', detail: err.message });
  }
});

// GET /api/user/session — retrieve or create current developer session
router.get('/user/session', async (req, res) => {
  try {
    const user = await getOrCreateUser(req.query.userId, 'developer');
    res.json({
      userId: user._id,
      email: user.email,
      tier: 'Developer Pro',
      unlimited: true,
      authRequired: false,
      scansToday: user.scansToday || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user session', detail: err.message });
  }
});

module.exports = router;
