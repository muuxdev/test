// validators.js - دوال التحقق من صحة البيانات

/**
 * التحقق من صحة البريد الإلكتروني
 */
export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
}

/**
 * التحقق من صحة رقم الهاتف
 */
export function isValidPhone(phone) {
  if (!phone || typeof phone !== 'string') return false;
  // قبول أرقام بطول 7-20 مع أرقام ورموز
  const phoneRegex = /^[\d\+\-\s\(\)]{7,20}$/;
  return phoneRegex.test(phone.trim());
}

/**
 * التحقق من صحة الأسعار (يجب أن تكون أكبر من صفر)
 */
export function isValidPrice(price) {
  const num = parseFloat(price);
  return !isNaN(num) && num >= 0;
}

/**
 * التحقق من صحة الكمية (يجب أن تكون عدد صحيح موجب)
 */
export function isValidQuantity(qty) {
  const num = parseInt(qty, 10);
  return !isNaN(num) && num >= 0;
}

/**
 * التحقق من صحة التاريخ
 */
export function isValidDate(dateString) {
  const date = new Date(dateString);
  return date instanceof Date && !isNaN(date.getTime());
}

/**
 * التحقق من صحة كود المنتج
 */
export function isValidProductCode(code) {
  if (!code || typeof code !== 'string') return false;
  // كود يجب أن يكون 3-20 حرف/رقم
  return /^[A-Za-z0-9\-_]{3,20}$/.test(code.trim());
}

/**
 * التحقق من صحة اسم
 */
export function isValidName(name) {
  if (!name || typeof name !== 'string') return false;
  // الاسم يجب أن يكون 2-100 حرف ويمكنه أن يحتوي على عربي وإنجليزي
  return name.trim().length >= 2 && name.trim().length <= 100;
}

/**
 * التحقق من صحة رقم الفاتورة
 */
export function isValidInvoiceNumber(invoiceNo) {
  if (!invoiceNo || typeof invoiceNo !== 'string') return false;
  // رقم فاتورة: INV-2024-001 أو مشابه
  return /^[A-Za-z0-9\-]{5,30}$/.test(invoiceNo.trim());
}

/**
 * التحقق من صحة كلمة المرور
 */
export function isValidPassword(password) {
  if (!password || typeof password !== 'string') return false;
  // كلمة المرور يجب أن تكون 6 أحرف على الأقل
  return password.length >= 6;
}

/**
 * التحقق من صحة URL
 */
export function isValidUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * دالة عامة للتحقق من البيانات المطلوبة
 */
export function validateRequired(data, requiredFields) {
  const errors = {};
  
  for (const field of requiredFields) {
    const value = data[field];
    if (value === null || value === undefined || String(value).trim() === '') {
      errors[field] = `${field} مطلوب`;
    }
  }
  
  return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * التحقق من صحة بيانات المنتج
 */
export function validateProduct(product) {
  const errors = {};
  
  if (!isValidName(product.name)) {
    errors.name = 'اسم المنتج يجب أن يكون 2-100 حرف';
  }
  
  if (!isValidProductCode(product.code)) {
    errors.code = 'كود المنتج يجب أن يكون 3-20 حرف/رقم';
  }
  
  if (!isValidPrice(product.buy_price)) {
    errors.buy_price = 'سعر الشراء يجب أن يكون موجباً';
  }
  
  if (!isValidPrice(product.sell_price)) {
    errors.sell_price = 'سعر البيع يجب أن يكون موجباً';
  }
  
  if (!isValidQuantity(product.stock_qty)) {
    errors.stock_qty = 'الكمية يجب أن تكون موجبة';
  }
  
  return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * التحقق من صحة بيانات العميل
 */
export function validateCustomer(customer) {
  const errors = {};
  
  if (!isValidName(customer.name)) {
    errors.name = 'اسم العميل مطلوب';
  }
  
  if (customer.phone && !isValidPhone(customer.phone)) {
    errors.phone = 'رقم الهاتف غير صحيح';
  }
  
  if (customer.email && !isValidEmail(customer.email)) {
    errors.email = 'البريد الإلكتروني غير صحيح';
  }
  
  return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * التحقق من صحة بيانات الفاتورة
 */
export function validateInvoice(invoice) {
  const errors = {};
  
  if (!isValidInvoiceNumber(invoice.invoice_no)) {
    errors.invoice_no = 'رقم الفاتورة غير صحيح';
  }
  
  if (!isValidName(invoice.customer_name)) {
    errors.customer_name = 'اسم العميل مطلوب';
  }
  
  if (!Array.isArray(invoice.items) || invoice.items.length === 0) {
    errors.items = 'الفاتورة يجب أن تحتوي على سلع واحدة على الأقل';
  }
  
  if (!isValidPrice(invoice.total)) {
    errors.total = 'المجموع يجب أن يكون موجباً';
  }
  
  if (!isValidDate(invoice.date)) {
    errors.date = 'التاريخ غير صحيح';
  }
  
  return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * التحقق من صحة بيانات الموظف
 */
export function validateEmployee(employee) {
  const errors = {};
  
  if (!isValidName(employee.name)) {
    errors.name = 'اسم الموظف مطلوب';
  }
  
  if (employee.phone && !isValidPhone(employee.phone)) {
    errors.phone = 'رقم الهاتف غير صحيح';
  }
  
  if (employee.email && !isValidEmail(employee.email)) {
    errors.email = 'البريد الإلكتروني غير صحيح';
  }
  
  if (!isValidPrice(employee.salary)) {
    errors.salary = 'الراتب يجب أن يكون موجباً';
  }
  
  return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * تنظيف وتطبيع البيانات
 */
export function sanitizeInput(input) {
  if (typeof input === 'string') {
    return input
      .trim()
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  return input;
}

/**
 * التحقق من صحة البيانات العددية
 */
export function isNumeric(value) {
  return !isNaN(parseFloat(value)) && isFinite(value);
}

export default {
  isValidEmail,
  isValidPhone,
  isValidPrice,
  isValidQuantity,
  isValidDate,
  isValidProductCode,
  isValidName,
  isValidInvoiceNumber,
  isValidPassword,
  isValidUrl,
  validateRequired,
  validateProduct,
  validateCustomer,
  validateInvoice,
  validateEmployee,
  sanitizeInput,
  isNumeric
};
