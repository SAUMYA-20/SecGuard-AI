require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const path = require('path');

const auditRoutes = require('./routes/audit');
const { getRedisStatus } = require('./queue/connection');

// Auto-register worker in-process so a single 'npm start' handles both API & queue execution
require('./workers/auditWorker');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Global API rate limit guardrail
app.use(
  '/api',
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);

app.use('/api', auditRoutes);

app.get('/api/health', (req, res) => {
  const geminiConfigured = Boolean(process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.startsWith('AQ.'));
  res.json({
    status: 'ok',
    mongo: mongoose.connection.readyState === 1,
    redis: getRedisStatus(),
    geminiConfigured,
    geminiModel: process.env.GEMINI_MODEL || 'gemini-3.6',
    timestamp: new Date().toISOString()
  });
});

async function start() {
  if (process.env.MONGODB_URI) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 5000
      });
      console.log('[server] Connected to MongoDB Atlas successfully');
    } catch (err) {
      console.warn('[server] MongoDB Atlas connection warning:', err.message);
      console.warn('[server] Continuing in standalone mode. To enable full persistence, check MONGODB_URI in .env');
    }
  } else {
    console.log('[server] MONGODB_URI not configured, operating with local state.');
  }

  app.listen(PORT, () => {
    console.log('====================================================');
    console.log(`⚡ SecGuard AI Gateway running at: http://localhost:${PORT}`);
    console.log(`✨ Gemini AI Reasoning Engine: Active (${process.env.GEMINI_MODEL || 'gemini-3.6'})`);
    console.log('====================================================');
  });
}

start();

module.exports = app;
