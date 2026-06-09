// logger.js - نظام تسجيل بسيط ومتوافق مع Winston
import winston from 'winston';

const isProduction = process.env.NODE_ENV === 'production';

const baseLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug'),
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
      const extra = Object.keys(meta || {}).length ? ` ${JSON.stringify(meta)}` : '';
      return `[${timestamp}] ${level.toUpperCase()}: ${stack || message}${extra}`;
    })
  ),
  transports: [new winston.transports.Console()]
});

function logWith(level, icon, args) {
  const [message, ...rest] = args;
  const text = typeof message === 'string' ? `${icon} ${message}` : message;
  try {
    baseLogger.log(level, text, rest.length ? { details: rest } : {});
  } catch {
    console.log(icon, ...args);
  }
}

const logger = {
  debug: (...args) => logWith('debug', '🔎', args),
  info: (...args) => logWith('info', 'ℹ️', args),
  success: (...args) => logWith('info', '✅', args),
  warn: (...args) => logWith('warn', '⚠️', args),
  error: (...args) => logWith('error', '❌', args),
  critical: (...args) => logWith('error', '🚨', args)
};

export function logOperation(action, details = {}) {
  logger.info(action, details);
}

export function logError(error, details = {}) {
  logger.error(error?.stack || error?.message || error, details);
}

export function logCritical(action, details = {}) {
  logger.critical(action, details);
}

export default logger;
