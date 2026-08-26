const Redis = require('ioredis');
require('dotenv').config();

let isRedisConnected = false;

// A single shared ioredis connection configured for BullMQ
const connection = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: Number(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  maxRetriesPerRequest: null,
  lazyConnect: true,
  enableOfflineQueue: false,
  retryStrategy(times) {
    if (times > 5) {
      // stop reconnect spam after 5 attempts
      return null;
    }
    return Math.min(times * 1000, 3000);
  }
});

connection.on('connect', () => {
  isRedisConnected = true;
  console.log('[redis] Connected to Redis broker successfully');
});

connection.on('ready', () => {
  isRedisConnected = true;
});

connection.on('error', (err) => {
  isRedisConnected = false;
  // Log once gracefully without crashing the server
  if (err.code === 'ECONNREFUSED') {
    // Redis server is not running locally
  } else {
    console.warn('[redis] connection notice:', err.message);
  }
});

connection.on('close', () => {
  isRedisConnected = false;
});

// Attempt initial connection without blocking boot
connection.connect().catch((err) => {
  console.log('[redis] Local Redis broker not detected (' + err.message + '). Standalone direct-audit mode active.');
});

function getRedisStatus() {
  return isRedisConnected;
}

module.exports = { connection, getRedisStatus };
