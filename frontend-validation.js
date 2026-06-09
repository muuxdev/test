// frontend-validation.js
// نظام Validation و Error Handling محسّن للواجهة الأمامية

/**
 * دوال التحقق من صحة البيانات (Validation)
 */
const Validators = {
  isValidEmail: (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
  },

  isValidPhone: (phone) => {
    const re = /^[\d\+\-\s\(\)]{7,20}$/;
    return re.test(String(phone));
  },

  isValidPrice: (price) => {
    const num = parseFloat(price);
    return !isNaN(num) && num >= 0;
  },

  isValidQuantity: (qty) => {
    const num = parseInt(qty, 10);
    return !isNaN(num) && num >= 0;
  },

  isValidDate: (dateString) => {
    const date = new Date(dateString);
    return date instanceof Date && !isNaN(date.getTime());
  },

  isValidProductCode: (code) => {
    return /^[A-Za-z0-9\-_]{3,20}$/.test(String(code).trim());
  },

  isValidName: (name) => {
    const str = String(name).trim();
    return str.length >= 2 && str.length <= 100;
  },

  isValidInvoice: (invoice) => {
    return /^[A-Za-z0-9\-]{5,30}$/.test(String(invoice).trim());
  },

  isValidPassword: (password) => {
    return String(password).length >= 6;
  }
};

/**
 * نظام رسائل الخطأ والنجاح المحسّن
 */
const ErrorHandler = {
  errors: [],
  warnings: [],

  addError: (message, context = null) => {
    const error = {
      message,
      context,
      timestamp: new Date().toISOString(),
      id: `error_${Date.now()}_${Math.random()}`
    };
    ErrorHandler.errors.push(error);
    console.error(`❌ [ERROR] ${message}`, context || '');
    return error.id;
  },

  addWarning: (message, context = null) => {
    const warning = {
      message,
      context,
      timestamp: new Date().toISOString()
    };
    ErrorHandler.warnings.push(warning);
    console.warn(`⚠️ [WARNING] ${message}`);
  },

  clearErrors: () => {
    ErrorHandler.errors = [];
  },

  clearWarnings: () => {
    ErrorHandler.warnings = [];
  },

  getLastError: () => {
    return ErrorHandler.errors[ErrorHandler.errors.length - 1] || null;
  },

  getErrorLog: () => {
    return {
      errors: ErrorHandler.errors,
      warnings: ErrorHandler.warnings,
      total: ErrorHandler.errors.length + ErrorHandler.warnings.length
    };
  },

  showErrorLog: () => {
    const log = ErrorHandler.getErrorLog();
    console.table(log);
  }
};

/**
 * معالج الأخطاء العام
 */
window.addEventListener('error', (event) => {
  ErrorHandler.addError('خطأ غير متوقع في الصفحة', {
    message: event.error?.message,
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno
  });
  toast('❌ حدث خطأ غير متوقع', 'error');
});

/**
 * معالج الـ Promise Rejections
 */
window.addEventListener('unhandledrejection', (event) => {
  ErrorHandler.addError('فشل في معالجة Promise', {
    reason: event.reason?.message || String(event.reason)
  });
  toast('❌ خطأ في معالجة البيانات', 'error');
  event.preventDefault();
});

/**
 * دالة محسّنة لـ API Calls مع معالجة الأخطاء
 */
async function apiCall(endpoint, options = {}) {
  const {
    method = 'GET',
    body = null,
    headers = {},
    timeout = 30000,
    showError = true
  } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const token = localStorage.getItem('token') || '';
    const API_BASE = window.API_BASE || '/api';

    const response = await fetch(API_BASE + endpoint, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` }),
        ...headers
      },
      body: body ? JSON.stringify(body) : null,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // معالجة الأخطاء حسب الـ Status Code
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({
        message: `خطأ ${response.status}`
      }));

      const errorMsg = errorData.message || errorData.error || `خطأ ${response.status}`;

      if (response.status === 401) {
        ErrorHandler.addError('جلستك انتهت', { status: 401 });
        localStorage.removeItem('token');
        if (typeof window.doLogout === 'function') { window.doLogout(); } else { window.location.href = '/frontend-updated.html'; }
      } else if (response.status === 403) {
        ErrorHandler.addError('ليس لديك صلاحيات لهذا الإجراء', { status: 403 });
      } else if (response.status === 429) {
        ErrorHandler.addError('تم تجاوز حد الطلبات، حاول لاحقاً', { status: 429 });
      } else {
        ErrorHandler.addError(errorMsg, { status: response.status });
      }

      if (showError) {
        toast(errorMsg, 'error');
      }

      throw new Error(errorMsg);
    }

    const data = await response.json();
    return data;

  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      const timeoutMsg = 'انتهت مهلة الاتصال، جرب مرة أخرى';
      ErrorHandler.addError(timeoutMsg);
      if (showError) toast(timeoutMsg, 'error');
    } else {
      ErrorHandler.addError(err.message, { endpoint, method });
      if (showError) toast(err.message || 'خطأ في الاتصال', 'error');
    }

    throw err;
  }
}

/**
 * دالة التحقق من صحة نموذج (Form Validation)
 */
function validateForm(formId, rules) {
  const form = document.getElementById(formId);
  if (!form) {
    ErrorHandler.addError(`لم يتم العثور على النموذج: ${formId}`);
    return false;
  }

  const errors = {};

  for (const [fieldName, fieldRules] of Object.entries(rules)) {
    const field = form.elements[fieldName];
    if (!field) {
      ErrorHandler.addWarning(`الحقل غير موجود: ${fieldName}`);
      continue;
    }

    const value = field.value.trim();

    for (const rule of fieldRules) {
      if (rule.required && !value) {
        errors[fieldName] = rule.message || `${fieldName} مطلوب`;
        break;
      }

      if (rule.pattern && !rule.pattern.test(value)) {
        errors[fieldName] = rule.message || `${fieldName} غير صحيح`;
        break;
      }

      if (rule.min && value.length < rule.min) {
        errors[fieldName] = rule.message || `${fieldName} يجب أن يكون ${rule.min} أحرف على الأقل`;
        break;
      }

      if (rule.max && value.length > rule.max) {
        errors[fieldName] = rule.message || `${fieldName} يجب أن لا يتجاوز ${rule.max} أحرف`;
        break;
      }

      if (rule.custom && !rule.custom(value)) {
        errors[fieldName] = rule.message || `${fieldName} غير صحيح`;
        break;
      }
    }
  }

  if (Object.keys(errors).length > 0) {
    ErrorHandler.addError('أخطاء في التحقق من البيانات', errors);
    // عرض الأخطاء بجانب الحقول
    Object.entries(errors).forEach(([field, message]) => {
      const fieldEl = form.elements[field];
      if (fieldEl) {
        fieldEl.classList.add('input-error');
        fieldEl.setAttribute('aria-invalid', 'true');
        const errorEl = fieldEl.parentElement?.querySelector('.error-message');
        if (errorEl) {
          errorEl.textContent = message;
          errorEl.style.display = 'block';
        }
      }
    });
    return false;
  }

  // تنظيف الأخطاء إذا كانت التحقق ناجحة
  Array.from(form.elements).forEach(el => {
    el.classList.remove('input-error');
    el.removeAttribute('aria-invalid');
  });

  return true;
}

/**
 * دالة محسّنة لـ toast مع أيقونات
 */
function toast(message, type = 'info', duration = 3000) {
  const icons = {
    success: '✅',
    error: '❌',
    warning: '⚠️',
    info: 'ℹ️'
  };

  const colors = {
    success: '#10b981',
    error: '#ef4444',
    warning: '#f59e0b',
    info: '#2563eb'
  };

  const container = document.getElementById('toastContainer') || (() => {
    const div = document.createElement('div');
    div.id = 'toastContainer';
    div.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;';
    document.body.appendChild(div);
    return div;
  })();

  const toastEl = document.createElement('div');
  toastEl.style.cssText = `
    background: ${colors[type]};
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 10px;
    animation: slideIn 0.3s ease;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    font-weight: 500;
  `;

  toastEl.innerHTML = `
    <span style="font-size: 18px;">${icons[type]}</span>
    <span>${message}</span>
  `;

  container.appendChild(toastEl);

  setTimeout(() => {
    toastEl.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toastEl.remove(), 300);
  }, duration);
}

/**
 * دالة لتنظيف وتطبيع البيانات (Sanitization)
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}

/**
 * دالة لتحميل البيانات مع Loading State
 */
async function loadDataSafely(loadFn, errorCallback = null) {
  try {
    if (typeof window.setLoading === 'function') window.setLoading(true);
    const data = await loadFn();
    if (typeof window.setLoading === 'function') window.setLoading(false);
    return data;
  } catch (err) {
    if (typeof window.setLoading === 'function') window.setLoading(false);
    if (errorCallback) {
      errorCallback(err);
    }
    throw err;
  }
}

/**
 * إضافة CSS للـ animations والـ styles
 */
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(400px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(400px); opacity: 0; }
  }
  
  .input-error {
    border-color: #ef4444 !important;
    background-color: #fee2e2 !important;
  }
  
  .input-error:focus {
    outline-color: #ef4444 !important;
    box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1) !important;
  }
  
  .error-message {
    color: #dc2626;
    font-size: 12px;
    margin-top: 4px;
    display: none;
    font-weight: 500;
  }

  .loading-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9998;
    backdrop-filter: blur(2px);
  }

  .spinner {
    border: 3px solid rgba(255, 255, 255, 0.3);
    border-top: 3px solid white;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
`;
document.head.appendChild(style);

/**
 * تصدير الكائنات
 */
window.Validators = Validators;
window.ErrorHandler = ErrorHandler;
window.apiCall = apiCall;
window.validateForm = validateForm;
window.toast = window.toast || toast;
window.frontendToast = toast;
window.sanitizeInput = sanitizeInput;
window.loadDataSafely = loadDataSafely;

console.log('%c✅ Frontend Validation System Loaded', 'color: #10b981; font-size: 14px; font-weight: bold');
