require('dotenv').config();
const { Worker } = require('bullmq');
const { connection } = require('../queue/connection');
const { QUEUE_NAME } = require('../queue/auditQueue');
const { executeAuditScan } = require('../services/auditRunner');

let worker = null;

try {
  worker = new Worker(
    QUEUE_NAME,
    async (job) => {
      const { url, userId } = job.data;
      console.log(`[worker] Processing BullMQ job ${job.id} -> ${url}`);

      const auditData = await executeAuditScan(url, userId);

      console.log(`[worker] Job ${job.id} complete — score ${auditData.score}/100 (${auditData.grade})`);
      return auditData;
    },
    { connection, concurrency: 5 }
  );

  worker.on('failed', (job, err) => {
    console.error(`[worker] Job ${job?.id} failed:`, err.message);
  });

  worker.on('completed', (job) => {
    console.log(`[worker] Job ${job.id} acknowledged`);
  });

  console.log('[worker] SecGuard AI audit worker listening on queue:', QUEUE_NAME);
} catch (err) {
  console.warn('[worker] BullMQ worker initialization warning:', err.message);
}

module.exports = worker;
