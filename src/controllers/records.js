/**
 * Records endpoints (GET /records and POST /records)
 * Handles fetching and applying DNS records
 */

const dnsmasqService = require('../services/dnsmasq');
const config = require('../config');
const logger = require('../utils/logger');

// Serialize reads and writes so applies cannot overlap and listings
// do not observe a half-written batch. Failures do not stall later work.
let workChain = Promise.resolve();
let workDepth = 0;

function rejectQueueFull(res) {
  logger.warn('Work queue full, rejecting request', {
    depth: workDepth,
    max: config.workQueueMax
  });
  res.setHeader('Retry-After', '1');
  return res.status(503).json({ error: 'Too many concurrent record operations' });
}

function enqueueExclusive(work) {
  if (workDepth >= config.workQueueMax) {
    return null;
  }

  workDepth++;
  const run = workChain.then(() => work());
  workChain = run.catch(() => {});
  return run.finally(() => {
    workDepth--;
  });
}

/**
 * Get all DNS records (GET /records)
 */
async function getRecords(req, res) {
  const acceptHeader = req.get('Accept');
  
  logger.debug('Get records request received', { accept: acceptHeader });
  
  // Validate Accept header
  if (acceptHeader && !acceptHeader.includes(config.contentType)) {
    logger.warn('Unsupported Accept header', { accept: acceptHeader });
    return res.status(406).json({ error: 'Not Acceptable' });
  }
  
  const queued = enqueueExclusive(() => dnsmasqService.getRecords());
  if (!queued) {
    return rejectQueueFull(res);
  }

  try {
    const records = await queued;
    
    // Set exact content type (no charset) for external-dns webhook protocol
    res.setHeader('Content-Type', config.contentType);
    res.send(JSON.stringify(records));
    
    logger.info('Get records response sent', { count: records.length });
    
  } catch (err) {
    logger.error('Failed to get records', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to retrieve DNS records' });
  }
}

/**
 * Apply DNS changes (POST /records)
 */
async function applyChanges(req, res) {
  const changes = req.body;

  if (!changes || typeof changes !== 'object' || Array.isArray(changes)) {
    logger.warn('Invalid request body for apply changes');
    return res.status(400).json({ error: 'Invalid request body' });
  }
  
  logger.debug('Apply changes request received', {
    createCount: (changes.create || []).length,
    updateCount: (changes.updateNew || []).length,
    deleteCount: (changes.delete || []).length
  });
  
  const queued = enqueueExclusive(() => dnsmasqService.applyChanges(changes));
  if (!queued) {
    return rejectQueueFull(res);
  }

  try {
    await queued;
    
    // Return 204 No Content on success (per external-dns spec)
    res.status(204).send();
    
    logger.info('Apply changes completed successfully');
    
  } catch (err) {
    logger.error('Failed to apply changes', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to apply DNS changes' });
  }
}

module.exports = {
  getRecords,
  applyChanges
};
