// cache.js - نظام الـ Caching باستخدام Redis

import redis from 'redis';
import logger from './logger.js';

let redisClient = null;
let cacheEnabled = false;

/**
 * تهيئة Redis Cache
 */
export async function initCache() {
  if (!process.env.REDIS_ENABLED || process.env.REDIS_ENABLED !== 'true') {
    logger.info('Redis Cache معطل - النظام سيعمل بدونه');
    cacheEnabled = false;
    return;
  }

  try {
    redisClient = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 500)
      }
    });

    redisClient.on('error', (err) => {
      logger.error(`Redis خطأ: ${err.message}`);
      cacheEnabled = false;
    });

    redisClient.on('connect', () => {
      logger.success('Redis Cache متصل بنجاح');
      cacheEnabled = true;
    });

    redisClient.on('ready', () => {
      logger.info('Redis Cache جاهز للاستخدام');
      cacheEnabled = true;
    });

    await redisClient.connect();
  } catch (err) {
    logger.warn(`فشل الاتصال بـ Redis: ${err.message}`);
    cacheEnabled = false;
  }
}

/**
 * حفظ بيانات في الـ Cache
 */
export async function setCache(key, value, expirationSeconds = 3600) {
  if (!cacheEnabled || !redisClient) return false;

  try {
    const serialized = JSON.stringify(value);
    await redisClient.setEx(key, expirationSeconds, serialized);
    logger.debug(`تم حفظ في Cache: ${key}`);
    return true;
  } catch (err) {
    logger.warn(`خطأ في حفظ Cache: ${err.message}`);
    return false;
  }
}

/**
 * استعادة بيانات من الـ Cache
 */
export async function getCache(key) {
  if (!cacheEnabled || !redisClient) return null;

  try {
    const data = await redisClient.get(key);
    if (data) {
      logger.debug(`استعادة من Cache: ${key}`);
      return JSON.parse(data);
    }
    return null;
  } catch (err) {
    logger.warn(`خطأ في استعادة Cache: ${err.message}`);
    return null;
  }
}

/**
 * حذف بيانات من الـ Cache
 */
export async function deleteCache(key) {
  if (!cacheEnabled || !redisClient) return false;

  try {
    await redisClient.del(key);
    logger.debug(`تم حذف من Cache: ${key}`);
    return true;
  } catch (err) {
    logger.warn(`خطأ في حذف Cache: ${err.message}`);
    return false;
  }
}

/**
 * حذف جميع بيانات الـ Cache التي تبدأ بـ pattern معين
 */
export async function deleteCachePattern(pattern) {
  if (!cacheEnabled || !redisClient) return false;

  try {
    const keys = await redisClient.keys(pattern);
    if (keys.length > 0) {
      await redisClient.del(keys);
      logger.info(`تم حذف ${keys.length} مفتاح من Cache`);
    }
    return true;
  } catch (err) {
    logger.warn(`خطأ في حذف Cache Pattern: ${err.message}`);
    return false;
  }
}

/**
 * تنظيف جميع الـ Cache
 */
export async function flushCache() {
  if (!cacheEnabled || !redisClient) return false;

  try {
    await redisClient.flushAll();
    logger.warn('تم حذف جميع بيانات الـ Cache');
    return true;
  } catch (err) {
    logger.warn(`خطأ في تنظيف Cache: ${err.message}`);
    return false;
  }
}

/**
 * الحصول على حالة الـ Cache
 */
export function isCacheEnabled() {
  return cacheEnabled;
}

/**
 * إغلاق اتصال Redis
 */
export async function closeCache() {
  if (redisClient) {
    try {
      await redisClient.quit();
      logger.info('تم قطع اتصال Redis بنجاح');
    } catch (err) {
      logger.error(`خطأ في قطع اتصال Redis: ${err.message}`);
    }
  }
}

/**
 * دالة مساعدة: Caching مع Callback
 */
export async function cacheOrFetch(key, fetchFn, expirationSeconds = 3600) {
  // حاول الحصول من الـ Cache أولاً
  const cached = await getCache(key);
  if (cached) return cached;

  // إذا لم توجد في الـ Cache، احصل على البيانات
  const data = await fetchFn();

  // احفظ في الـ Cache
  await setCache(key, data, expirationSeconds);

  return data;
}

/**
 * مفاتيح Cache شاملة
 */
export const CacheKeys = {
  // المنتجات
  PRODUCTS: 'cache:products',
  PRODUCT: (id) => `cache:product:${id}`,
  PRODUCTS_BY_CATEGORY: (cat) => `cache:products:category:${cat}`,

  // العملاء
  CUSTOMERS: 'cache:customers',
  CUSTOMER: (id) => `cache:customer:${id}`,

  // الموردين
  SUPPLIERS: 'cache:suppliers',
  SUPPLIER: (id) => `cache:supplier:${id}`,

  // المبيعات
  SALES: 'cache:sales',
  SALES_DAILY: 'cache:sales:daily',
  SALES_MONTHLY: 'cache:sales:monthly',

  // المشتريات
  PURCHASES: 'cache:purchases',

  // الموظفين
  EMPLOYEES: 'cache:employees',

  // التقارير
  REPORTS: 'cache:reports',
  REPORT_DAILY: 'cache:report:daily',
  REPORT_MONTHLY: 'cache:report:monthly',
  REPORT_INVENTORY: 'cache:report:inventory',

  // الإحصائيات
  STATS: 'cache:stats',
  STATS_OVERVIEW: 'cache:stats:overview'
};

export default {
  initCache,
  setCache,
  getCache,
  deleteCache,
  deleteCachePattern,
  flushCache,
  isCacheEnabled,
  closeCache,
  cacheOrFetch,
  CacheKeys
};
