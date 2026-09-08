/**
 * JWT Authentication middleware
 */

const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const config = require('../config');

const EXPECTED_ISSUER = 'external-dns-proxy';

/**
 * JWT authentication middleware
 * Validates Bearer token in Authorization header
 */
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Authentication failed: Missing or invalid Authorization header', {
      path: req.path,
      method: req.method,
      hasAuthHeader: !!authHeader
    });
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header'
    });
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    const decoded = jwt.verify(token, config.sharedSecret, {
      algorithms: ['HS256']
    });

    if (decoded.iss !== EXPECTED_ISSUER || !decoded.exp) {
      throw new Error('Token missing required claims');
    }

    req.auth = decoded;

    logger.debug('Authentication successful', {
      path: req.path,
      method: req.method,
      issuer: decoded.iss || 'unknown'
    });

    next();
  } catch (err) {
    logger.warn('Authentication failed: Invalid token', {
      path: req.path,
      method: req.method,
      error: err.message
    });

    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid authentication token'
    });
  }
}

module.exports = authenticate;