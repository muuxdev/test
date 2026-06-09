// helpers.js - دوال مساعدة عامة

import logger from './logger.js';
import { sanitizeInput, isNumeric } from './validators.js';

/**
 * معالج الأخطاء الآمن
 */
export function handleError(res, error, defaultMessage = 'حدث خطأ') {
  logger.error(`API Error: ${error.message}`);
  
  const statusCode = error.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? defaultMessage 
    : error.message;

  return res.status(statusCode).json({
    success: false,
    error: message,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV !== 'production' && { details: error.message })
  });
}

/**
 * استجابة نجاح موحدة
 */
export function successResponse(res, data, message = 'العملية نجحت', statusCode = 200) {
  return res.status(statusCode).json({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  });
}

/**
 * استجابة خطأ موحدة
 */
export function errorResponse(res, message, statusCode = 400, details = null) {
  const response = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (details && process.env.NODE_ENV !== 'production') {
    response.details = details;
  }

  return res.status(statusCode).json(response);
}

/**
 * تنسيق البيانات المالية
 */
export function formatMoney(amount) {
  const num = parseFloat(amount || 0);
  if (!isNumeric(num)) return '0 د.إ';
  return num.toLocaleString('ar-AE', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }) + ' د.إ';
}

/**
 * تنسيق التاريخ بصيغة عربية
 */
export function formatDate(date) {
  if (!date) return '';
  const d = new Date(date);
  if (isNaN(d.getTime())) return '';
  
  return d.toLocaleDateString('ar-AE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
}

/**
 * تنسيق التاريخ والوقت
 */
export function formatDateTime(date) {
  if (!date) return '';
  const d = new Date(date);
  if (isNaN(d.getTime())) return '';
  
  return d.toLocaleDateString('ar-AE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * حساب الفرق بين تاريخين بالأيام
 */
export function daysDifference(date1, date2) {
  const d1 = new Date(date1);
  const d2 = new Date(date2);
  const diffTime = Math.abs(d2 - d1);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

/**
 * إنشاء معرّف فريد
 */
export function generateId(prefix = 'id') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * إنشاء رقم فاتورة
 */
export function generateInvoiceNumber(prefix = 'INV') {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
  return `${prefix}-${year}-${month}-${random}`;
}

/**
 * حساب الإجمالي مع الضريبة
 */
export function calculateTotal(subtotal, taxPercentage = 0) {
  const sub = parseFloat(subtotal || 0);
  const tax = (sub * parseFloat(taxPercentage || 0)) / 100;
  return sub + tax;
}

/**
 * حساب الربح
 */
export function calculateProfit(revenue, cost) {
  const r = parseFloat(revenue || 0);
  const c = parseFloat(cost || 0);
  return r - c;
}

/**
 * حساب نسبة الربح
 */
export function calculateProfitMargin(revenue, cost) {
  const r = parseFloat(revenue || 0);
  const c = parseFloat(cost || 0);
  if (r === 0) return 0;
  return ((r - c) / r) * 100;
}

/**
 * تجميع البيانات حسب نوع معين
 */
export function groupBy(array, key) {
  return array.reduce((acc, obj) => {
    const groupKey = obj[key];
    if (!acc[groupKey]) {
      acc[groupKey] = [];
    }
    acc[groupKey].push(obj);
    return acc;
  }, {});
}

/**
 * حساب الإحصائيات الأساسية
 */
export function calculateStats(numbers) {
  if (!numbers || numbers.length === 0) {
    return { sum: 0, avg: 0, min: 0, max: 0, count: 0 };
  }

  const nums = numbers.map(n => parseFloat(n || 0));
  const sum = nums.reduce((a, b) => a + b, 0);
  const count = nums.length;

  return {
    sum,
    avg: sum / count,
    min: Math.min(...nums),
    max: Math.max(...nums),
    count
  };
}

/**
 * فلترة البيانات بناءً على الشروط
 */
export function filterByConditions(data, conditions) {
  return data.filter(item => {
    return Object.keys(conditions).every(key => {
      const condition = conditions[key];
      if (typeof condition === 'function') {
        return condition(item[key]);
      }
      return item[key] === condition;
    });
  });
}

/**
 * ترتيب البيانات
 */
export function sortBy(array, key, order = 'asc') {
  return [...array].sort((a, b) => {
    const aVal = a[key];
    const bVal = b[key];

    if (order === 'asc') {
      return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
    } else {
      return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
    }
  });
}

/**
 * دمج كائنات متعددة
 */
export function mergeObjects(...objects) {
  return Object.assign({}, ...objects);
}

/**
 * تحويل مصفوفة إلى CSV
 */
export function arrayToCsv(array, headers = null) {
  if (!array || array.length === 0) return '';

  const keys = headers || Object.keys(array[0]);
  
  const csvHeaders = keys.map(k => `"${k}"`).join(',');
  
  const csvRows = array.map(item => {
    return keys.map(k => {
      const value = item[k];
      if (value === null || value === undefined) return '';
      const stringValue = String(value).replace(/"/g, '""');
      return `"${stringValue}"`;
    }).join(',');
  });

  return [csvHeaders, ...csvRows].join('\n');
}

/**
 * تحديد عمر الكوكيز والجلسة
 */
export const SESSION_CONFIG = {
  JWT_EXPIRES_IN: '7d',
  REFRESH_TOKEN_EXPIRES_IN: '30d',
  SESSION_TIMEOUT: 30 * 60 * 1000 // 30 دقيقة
};

/**
 * قوائم ثابتة مشتركة
 */
export const CONSTANTS = {
  ROLES: {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    MANAGER: 'manager',
    ACCOUNTANT: 'accountant',
    SELLER: 'seller',
    VIEWER: 'viewer'
  },

  DEPARTMENTS: [
    'إدارة عامة',
    'مبيعات',
    'حسابات',
    'مشتريات',
    'مستودع',
    'توصيل',
    'إدارة'
  ],

  PRODUCT_CATEGORIES: [
    'جلسات',
    'كنب',
    'غرف نوم',
    'طاولات',
    'ستائر',
    'أكسسوارات',
    'أخرى'
  ],

  PAYMENT_TYPES: [
    'كاش',
    'شيك',
    'تحويل بنكي',
    'بطاقة ائتمان',
    'أجل'
  ],

  INVOICE_STATUS: [
    'مسودة',
    'صادرة',
    'مدفوعة',
    'معلقة',
    'ملغاة'
  ],

  INSTALLMENT_STATUS: [
    'معلقة',
    'جارية',
    'مدفوعة',
    'متأخرة'
  ]
};

/**
 * دالة لتسجيل الإجراءات المهمة (مع الـ cache invalidation)
 */
export function invalidateCache(pattern) {
  // هذه الدالة ستُستدعى لمسح الـ cache عند تعديل البيانات
  // سيتم ربطها مع نظام الـ cache المركزي
  logger.debug(`Cache invalidation pattern: ${pattern}`);
}

export default {
  handleError,
  successResponse,
  errorResponse,
  formatMoney,
  formatDate,
  formatDateTime,
  daysDifference,
  generateId,
  generateInvoiceNumber,
  calculateTotal,
  calculateProfit,
  calculateProfitMargin,
  groupBy,
  calculateStats,
  filterByConditions,
  sortBy,
  mergeObjects,
  arrayToCsv,
  SESSION_CONFIG,
  CONSTANTS,
  invalidateCache
};
