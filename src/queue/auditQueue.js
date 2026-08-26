const { Queue } = require('bullmq');
const { connection, getRedisStatus } = require('./connection');
const { executeAuditScan } = require('../services/auditRunner');

const QUEUE_NAME = 'website-audit-queue';

let auditQueue = null;

try {
  auditQueue = new Queue(QUEUE_NAME, { connection });
} catch (err) {
  console.warn('[queue] BullMQ Queue initialization notice:', err.message);
}

// In-memory job store
const inMemoryJobs = new Map();

/**
 * Enqueue an asynchronous audit job. Returns immediately with a job id.
 */
async function dispatchAuditJob(url, userId) {
  const isRedisUp = getRedisStatus();

  if (isRedisUp && auditQueue) {
    try {
      const job = await auditQueue.add(
        'run-audit',
        { url, userId },
        {
          attempts: 3,
          backoff: { type: 'exponential', delay: 1000 },
          removeOnComplete: { age: 3600, count: 1000 },
          removeOnFail: { age: 86400 }
        }
      );
      return job.id;
    } catch (err) {
      console.warn('[queue] BullMQ dispatch failed, switching to in-memory execution:', err.message);
    }
  }

  // Fallback: asynchronous in-memory execution
  const jobId = 'local_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
  inMemoryJobs.set(jobId, {
    id: jobId,
    state: 'active',
    returnvalue: null,
    failedReason: null,
    createdAt: Date.now()
  });

  // Execute asynchronously out-of-band so response returns immediately
  setImmediate(async () => {
    try {
      const result = await executeAuditScan(url, userId);
      const existing = inMemoryJobs.get(jobId);
      if (existing) {
        existing.state = 'completed';
        existing.returnvalue = result;
      }
    } catch (scanErr) {
      console.error('[queue] Scan execution error:', scanErr.message);
      const existing = inMemoryJobs.get(jobId);
      if (existing) {
        existing.state = 'failed';
        existing.failedReason = scanErr.message;
      }
    }
  });

  return jobId;
}

/**
 * Poll job status and result by jobId
 */
async function getJobStatus(jobId) {
  if (typeof jobId === 'string' && jobId.startsWith('local_')) {
    const localJob = inMemoryJobs.get(jobId);
    if (!localJob) return null;
    return {
      id: localJob.id,
      state: localJob.state,
      returnvalue: localJob.returnvalue,
      failedReason: localJob.failedReason
    };
  }

  if (auditQueue) {
    try {
      const job = await auditQueue.getJob(jobId);
      if (job) {
        const state = await job.getState();
        
        // If a job got stuck in waiting for over 4 seconds, process in-flight
        if (state === 'waiting' && (Date.now() - (job.timestamp || Date.now())) > 4000) {
          console.log(`[queue] Job ${jobId} waiting in queue — running inline execution fallback.`);
          try {
            const auditData = await executeAuditScan(job.data.url, job.data.userId);
            return {
              id: job.id,
              state: 'completed',
              returnvalue: auditData,
              failedReason: null
            };
          } catch (inlineErr) {
            console.error('[queue] Inline execution failed:', inlineErr.message);
          }
        }

        return {
          id: job.id,
          state,
          returnvalue: job.returnvalue,
          failedReason: job.failedReason
        };
      }
    } catch (err) {
      // Fallback check in local memory
    }
  }

  return inMemoryJobs.get(jobId) || null;
}

module.exports = { auditQueue, dispatchAuditJob, getJobStatus, QUEUE_NAME };
