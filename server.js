import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import compression from 'compression';

// Import helpers and utilities
import logger, { logOperation, logError, logCritical } from './logger.js';
import { initCache, setCache, getCache, deleteCache, deleteCachePattern, CacheKeys, closeCache } from './cache.js';
import { 
  validateProduct, 
  validateCustomer, 
  validateInvoice, 
  validateEmployee,
  sanitizeInput 
} from './validators.js';
import { 
  successResponse, 
  errorResponse, 
  generateInvoiceNumber,
  formatMoney,
  formatDate,
  CONSTANTS,
  calculateProfitMargin
} from './helpers.js';

const { Pool } = pg;

dotenv.config();

// ═══════════════════════════════════════
// التحقق من متغيرات البيئة المهمة
// ═══════════════════════════════════════
function validateEnvironment() {
  const requiredEnvs = ['JWT_SECRET'];
  const missing = requiredEnvs.filter(env => !process.env[env]);
  
  if (missing.length > 0) {
    logger.error(`❌ متغيرات بيئة مفقودة: ${missing.join(', ')}`);
    console.error(`❌ الرجاء تعيين: ${missing.join(', ')} في ملف .env`);
    process.exit(1);
  }
  
  logger.success('✅ جميع متغيرات البيئة موجودة');
}

validateEnvironment();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Render يعمل خلف Reverse Proxy.
// هذا السطر ضروري حتى express-rate-limit لا يرمي خطأ X-Forwarded-For.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

// ═══════════════════════════════════════
// إعداد قاعدة البيانات مع معالجة الأخطاء
// ═══════════════════════════════════════
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
      }
    : {
        host: process.env.PGHOST || '127.0.0.1',
        port: Number(process.env.PGPORT || 5432),
        database: process.env.PGDATABASE || 'bq_furniture',
        user: process.env.PGUSER || 'bq_user',
        password: process.env.PGPASSWORD || 'bq_password'
      }
);

// معالجات أخطاء قاعدة البيانات
pool.on('error', (err, client) => {
  logCritical('Database Connection Error', {
    error: err.message,
    code: err.code,
    timestamp: new Date().toISOString()
  });
  console.error('❌ خطأ في اتصال قاعدة البيانات:', err);
});

pool.on('connect', () => {
  logger.success('✅ تم الاتصال بقاعدة البيانات PostgreSQL');
});

// اختبار الاتصال الأولي
async function testDatabaseConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    logger.success(`✅ اتصال قاعدة البيانات: ${result.rows[0].now}`);
    return true;
  } catch (err) {
    logError(err, { context: 'Database Connection Test' });
    return false;
  }
}

// Middleware
const allowedOrigins = [
  'https://test-dxen.onrender.com',
  ...(process.env.ALLOWED_ORIGIN || '')
    .split(',')
    .map(origin => origin.trim().replace(/\/$/, ''))
    .filter(Boolean)
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    const normalizedOrigin = String(origin).trim().replace(/\/$/, '');

    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(normalizedOrigin)) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(normalizedOrigin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-BQ-Source',
    'X-BQ-Page',
    'X-User-Email'
  ]
};
// ═══════════════════════════════════════
// Rate Limiting Configuration
// ═══════════════════════════════════════
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || 900000), // 15 دقيقة
  // V30: الواجهة ممكن تفضل مفتوحة 24 ساعة، لذلك لا نطبّق Rate Limit على طلبات القراءة GET/HEAD/OPTIONS.
  // التقييد يظل على عمليات الكتابة فقط POST/PUT/DELETE لحماية السيرفر بدون كسر الـ Live Sync.
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || 5000),
  message: { success: false, error: 'تم تجاوز حد الطلبات، يرجى المحاولة لاحقاً' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
    return req.path === '/api/health';
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 5, // 5 محاولات
  message: 'تم تجاوز محاولات تسجيل الدخول، يرجى المحاولة بعد 15 دقيقة',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // لا تحسب المحاولات الناجحة
});

// ═══════════════════════════════════════
// تطبيق Middleware
// ═══════════════════════════════════════
// Helmet - تحسين الأمان
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Single-file HTML pages in this project use inline scripts and onclick handlers.
      // scriptSrcAttr is required specifically for onclick/onchange inline handlers.
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      scriptSrcElem: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      scriptSrcAttr: ["'unsafe-inline'"],
styleSrc: [
  "'self'",
  "'unsafe-inline'",
  'https://fonts.googleapis.com',
  'https://p.typekit.net',
  'https://*.typekit.net'
],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com'],
connectSrc: [
  "'self'",
  'http://localhost:*',
  'http://127.0.0.1:*',
  'https://cdn.jsdelivr.net',
  'https://*.jsdelivr.net'
],      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"]
    }
  }
}));

// Compression - ضغط الاستجابات
app.use(compression());

// CORS
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

// Body Parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// General Rate Limiting
app.use('/api', generalLimiter);

// Logging Middleware
app.use((req, res, next) => {
  // V30: لا نزحم التيرمنال بطلبات القراءة الدورية؛ سجّل فقط عمليات الكتابة واللوجين والأخطاء.
  const noisyReadPaths = new Set(['/api/state/all', '/api/monitor/logs', '/api/monitor/stats', '/api/admin/overview', '/api/login-users']);
  if (!(req.method === 'GET' && noisyReadPaths.has(req.path))) {
    logOperation('API Request', {
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('user-agent')?.substring(0, 50)
    });
  }
  next();
});

const adminDir = path.join(__dirname, 'admin');
let requestCount = 0;
const serverStartedAt = Date.now();

app.use((req, res, next) => {
  requestCount += 1;
  next();
});

app.use(attachActivityAutoLogger);

// Admin React dashboard is served on a separate link: /admin
app.use('/admin', express.static(adminDir));

// Main HTML files can still be served from the project root.
app.use(express.static('public'));
app.use(express.static('.'));

// ═══════════════════════════════════════
// Defaults
// ═══════════════════════════════════════
const DEFAULT_PRODUCTS = [
  {id:'p001',code:'ST-330', name:'الستارة الويف 330 المتر',    category:'ستائر',  buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p002',code:'JL-ZAN', name:'جلسة المصري الزان',          category:'جلسات',  buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p003',code:'JL-MGR', name:'جلسة المغربي',               category:'جلسات',  buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p004',code:'JL-DCR', name:'جلسة محلي بديكور خشب',      category:'جلسات',  buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p005',code:'FR-001', name:'فرحة',                        category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p006',code:'MR-SHR', name:'مربع شرايح',                 category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p007',code:'MR-SAD', name:'مربع سادة',                  category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p008',code:'MR-DCR', name:'مربع سادة مع ديكور خشب',    category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p009',code:'YD-DWR', name:'يد دوران مع ديكور خشب',     category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p010',code:'MR-MTH', name:'مربع يد متحركة',             category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p011',code:'FY-001', name:'فيونكة',                     category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p012',code:'HW-QDM', name:'حوض قديم',                  category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p013',code:'MS-RQB', name:'مسطرة برقبة',               category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p014',code:'HL-TAJ', name:'حلايا تاج',                 category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p015',code:'HL-BDN', name:'حلايا بدون تاج',            category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p016',code:'MS-MHL', name:'مسطرة سادة محلي',           category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p017',code:'KK-001', name:'كوكتيل',                    category:'كنب',    buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p018',code:'NC-SLV', name:'نيو كلاسيك سلفر',          category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
  {id:'p019',code:'NC-BNI', name:'نيو كلاسيك بني',           category:'غرف نوم', buy_price:0, sell_price:0, stock_qty:0, notes:''},
];

const DEFAULT_STATE = {
  bq_products: DEFAULT_PRODUCTS,
  bq_sales: [],
  bq_customers: [],
  bq_suppliers: [],
  bq_expenses: [],
  bq_purchases: [],
  bq_installments: [],
  bq_employees: [],
  bq_leaves: [],
  bq_pur_inst: [],
  bq_settings: {},
  bq_inv_counter: 1,
  bq_qt_counter: 1
};

const ALLOWED_STATE_KEYS = new Set(Object.keys(DEFAULT_STATE));

const DEFAULT_USERS = [
  // Frontend-only users. Dashboard access users live in dashboard_users and must not appear here.
  // manager@binqazamel.ae is NOT auto-created anymore; create frontend managers manually from Admin > Frontend Users.
  { email:'accountant@binqazamel.ae', password:'3333', name:'ملاك علي',           role:'accountant', dept:'حسابات' },
  { email:'ahmed@binqazamel.ae',      password:'1111', name:'أحمد رفعت',          role:'seller',     dept:'مبيعات' },
  { email:'haitham@binqazamel.ae',    password:'2222', name:'هيثم أبو عرب',       role:'seller',     dept:'مبيعات' }
];


const DEFAULT_DASHBOARD_USERS = [
  { email:'admin@binqazamel.ae', password:'1234', name:'مدير لوحة التحكم', role:'super_admin', dept:'لوحة التحكم' },
  { email:'admin@bq-furniture.com', password:'admin123', name:'Admin', role:'super_admin', dept:'لوحة التحكم' }
];

const DASHBOARD_PERMISSIONS = ['overview','manageUsers','dataControl','backup','monitor'];

function defaultDashboardPermissionsForRole(role) {
  if (role === 'super_admin') {
    return { overview:true, manageUsers:true, dataControl:true, backup:true, monitor:true };
  }
  if (role === 'admin') {
    return { overview:true, manageUsers:false, dataControl:true, backup:false, monitor:true };
  }
  if (role === 'viewer') {
    return { overview:true, manageUsers:false, dataControl:false, backup:false, monitor:true };
  }
  return { overview:true, manageUsers:false, dataControl:false, backup:false, monitor:false };
}

const FRONTEND_MODULES = [
  'dashboard','sales','invoice','installments','all-invoices','products','customers',
  'purchases','pur-inst','suppliers','expenses','inventory','reports','employees','payroll','leaves','settings'
];

const SELLER_MODULES = ['invoice','quotation','installments','sales'];

function defaultPermissionsForRole(role) {
  if (role === 'seller') {
    return { modules: ['sales','invoice','installments'], sellerModules: [...SELLER_MODULES], dataControl: false, manageUsers: false, backup: false };
  }
  if (role === 'accountant') {
    return { modules: ['all-invoices','installments','reports','expenses','purchases','pur-inst','payroll'], sellerModules: [], dataControl: false, manageUsers: false, backup: false };
  }
  return { modules: [...FRONTEND_MODULES], sellerModules: [...SELLER_MODULES], dataControl: true, manageUsers: true, backup: true };
}

const STATE_LABELS = {
  bq_products: 'المنتجات',
  bq_sales: 'المبيعات والفواتير',
  bq_customers: 'العملاء',
  bq_suppliers: 'الموردين',
  bq_expenses: 'المصروفات',
  bq_purchases: 'المشتريات',
  bq_installments: 'الأقساط والآجل',
  bq_employees: 'الموظفون',
  bq_leaves: 'الإجازات',
  bq_pur_inst: 'آجل المشتريات',
  bq_settings: 'إعدادات الواجهة',
  bq_inv_counter: 'عداد الفواتير',
  bq_qt_counter: 'عداد عروض الأسعار'
};

// ═══════════════════════════════════════
// PostgreSQL helpers
// ═══════════════════════════════════════
async function q(text, params = []) {
  return pool.query(text, params);
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim();
}

function inferActivitySource(req) {
  const explicit = req.headers['x-bq-source'] || req.body?.source;
  if (explicit) return String(explicit).slice(0, 60);
  const ref = String(req.headers.referer || '').toLowerCase();
  if (ref.includes('/admin')) return 'admin';
  if (ref.includes('frontend-updated') || ref.includes('frontend')) return 'frontend';
  return 'api';
}

function jsonSafe(value, maxLen = 3500) {
  try {
    const text = JSON.stringify(value ?? {});
    if (text.length <= maxLen) return value ?? {};
    return { truncated: true, preview: text.slice(0, maxLen) };
  } catch {
    return { unsupported: true };
  }
}

function safeBodyDetails(req) {
  const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
  for (const key of ['password', 'newPassword', 'token']) delete body[key];
  const details = { method: req.method, path: req.originalUrl || req.path, bodyKeys: Object.keys(body) };
  if (body.email) details.email = body.email;
  if (body.name) details.name = body.name;
  if (body.code) details.code = body.code;
  if (body.invoice_no) details.invoice_no = body.invoice_no;
  if (body.key) details.key = body.key;
  if (req.params && Object.keys(req.params).length) details.params = req.params;
  if (req.query && Object.keys(req.query).length) details.query = req.query;
  return jsonSafe(details);
}

function sectionLabel(key) {
  return STATE_LABELS[key] || key || '';
}

function compactText(value, max = 70) {
  return String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max);
}

function firstDefined(...values) {
  return values.find(v => v !== undefined && v !== null && String(v).trim() !== '');
}

function countValueRecords(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return value === undefined ? 0 : 1;
}

function namedRecordFromBody(body = {}) {
  const item = body.item || body.record || body.product || body.customer || body.supplier || body.employee || body.expense || body.purchase || body.sale || body;
  const name = firstDefined(item.name, item.customer_name, item.supplier_name, item.employee_name, item.title, item.description, body.name, body.customer_name, body.supplier_name);
  const code = firstDefined(item.code, body.code, item.invoice_no, body.invoice_no);
  const total = firstDefined(item.total, body.total, item.amount, body.amount);
  const bits = [];
  if (name) bits.push(compactText(name));
  if (code) bits.push(`كود/رقم: ${compactText(code, 35)}`);
  if (total !== undefined && total !== null && total !== '') bits.push(`القيمة: ${compactText(total, 20)}`);
  return bits.length ? ` (${bits.join(' — ')})` : '';
}


function formatLogMoney(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return compactText(value, 30);
  return n.toLocaleString('en-US', { maximumFractionDigits: 2 }) + ' د.إ';
}

function formatLogDate(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return compactText(value, 30);
  return d.toISOString().slice(0, 10);
}

function stableRecordKey(sectionKey, row = {}, index = 0) {
  if (!row || typeof row !== 'object') return `idx:${index}`;
  const candidates = [row.db_id, row._id, row.id, row.legacy_id, row.legacyId];
  if (sectionKey === 'bq_products') candidates.push(row.code, row.name);
  if (sectionKey === 'bq_sales' || sectionKey === 'bq_purchases') candidates.push(row.invoice_no, row.invoiceNo);
  if (sectionKey === 'bq_customers' || sectionKey === 'bq_suppliers') candidates.push(row.email, row.phone, row.name, row.customer_name, row.supplier_name);
  if (sectionKey === 'bq_expenses') candidates.push(row.title, row.category && row.amount && row.date ? `${row.category}:${row.amount}:${row.date}` : null);
  if (sectionKey === 'bq_installments' || sectionKey === 'bq_pur_inst') candidates.push(row.invoice_no, row.customer_name && row.amount ? `${row.customer_name}:${row.amount}:${row.due_date || ''}` : null, row.supplier_name && row.amount ? `${row.supplier_name}:${row.amount}:${row.due_date || ''}` : null);
  if (sectionKey === 'bq_employees') candidates.push(row.email, row.phone, row.name);
  if (sectionKey === 'bq_leaves') candidates.push(row.employee_name && row.from_date ? `${row.employee_name}:${row.from_date}:${row.to_date || ''}` : null);
  const v = candidates.find(x => x !== undefined && x !== null && String(x).trim() !== '');
  return v ? String(v) : `idx:${index}`;
}

function comparableRecord(row) {
  if (!row || typeof row !== 'object') return row;
  const clone = { ...row };
  delete clone.updatedAt; delete clone.updated_at; delete clone.createdAt; delete clone.created_at;
  delete clone.updatedBy; delete clone.updated_by; delete clone.createdByDisplay;
  return clone;
}

function stableJson(value) {
  return JSON.stringify(value, Object.keys(value || {}).sort());
}

function sectionRecordLabel(sectionKey, row = {}) {
  const bits = [];
  if (!row || typeof row !== 'object') return '';
  if (sectionKey === 'bq_products') {
    bits.push(`المنتج: ${compactText(row.name || row.title || row.code || 'بدون اسم', 70)}`);
    if (row.code) bits.push(`الكود: ${compactText(row.code, 40)}`);
    if (row.category) bits.push(`الفئة: ${compactText(row.category, 40)}`);
    if (row.sell_price || row.buy_price) bits.push(`سعر البيع: ${formatLogMoney(row.sell_price || 0)}`);
  } else if (sectionKey === 'bq_sales') {
    bits.push(`الفاتورة: ${compactText(row.invoice_no || row.invoiceNo || row.id || '', 50)}`);
    if (row.customer_name) bits.push(`العميل: ${compactText(row.customer_name, 60)}`);
    bits.push(`الإجمالي: ${formatLogMoney(row.total || 0)}`);
    if (row.paid !== undefined) bits.push(`المدفوع: ${formatLogMoney(row.paid || 0)}`);
    if (row.remaining !== undefined) bits.push(`المتبقي: ${formatLogMoney(row.remaining || 0)}`);
  } else if (sectionKey === 'bq_purchases') {
    bits.push(`فاتورة شراء: ${compactText(row.invoice_no || row.invoiceNo || row.id || '', 50)}`);
    if (row.supplier_name) bits.push(`المورد: ${compactText(row.supplier_name, 60)}`);
    bits.push(`الإجمالي: ${formatLogMoney(row.total || 0)}`);
  } else if (sectionKey === 'bq_expenses') {
    const cat = row.category || row.title || row.name || 'عام';
    bits.push(`الفئة: ${compactText(cat, 60)}`);
    bits.push(`المبلغ: ${formatLogMoney(row.amount || row.total || 0)}`);
    const d = formatLogDate(row.date || row.createdAt || row.created_at);
    if (d) bits.push(`التاريخ: ${d}`);
    if (row.notes) bits.push(`البيان: ${compactText(row.notes, 70)}`);
  } else if (sectionKey === 'bq_customers') {
    bits.push(`العميل: ${compactText(row.name || row.customer_name || 'بدون اسم', 70)}`);
    if (row.phone) bits.push(`الهاتف: ${compactText(row.phone, 30)}`);
  } else if (sectionKey === 'bq_suppliers') {
    bits.push(`المورد: ${compactText(row.name || row.supplier_name || 'بدون اسم', 70)}`);
    if (row.phone) bits.push(`الهاتف: ${compactText(row.phone, 30)}`);
  } else if (sectionKey === 'bq_installments') {
    bits.push(`قسط للعميل: ${compactText(row.customer_name || row.customer || 'غير محدد', 60)}`);
    bits.push(`المبلغ: ${formatLogMoney(row.amount || row.total || 0)}`);
    if (row.remaining !== undefined) bits.push(`المتبقي: ${formatLogMoney(row.remaining || 0)}`);
    const d = formatLogDate(row.due_date || row.dueDate);
    if (d) bits.push(`الاستحقاق: ${d}`);
  } else if (sectionKey === 'bq_pur_inst') {
    bits.push(`قسط مشتريات للمورد: ${compactText(row.supplier_name || row.supplier || 'غير محدد', 60)}`);
    bits.push(`المبلغ: ${formatLogMoney(row.amount || row.total || 0)}`);
    if (row.remaining !== undefined) bits.push(`المتبقي: ${formatLogMoney(row.remaining || 0)}`);
  } else if (sectionKey === 'bq_employees') {
    bits.push(`الموظف: ${compactText(row.name || 'بدون اسم', 70)}`);
    if (row.role) bits.push(`الوظيفة: ${compactText(row.role, 50)}`);
    if (row.total || row.salary) bits.push(`الراتب/الإجمالي: ${formatLogMoney(row.total || row.salary || 0)}`);
  } else if (sectionKey === 'bq_leaves') {
    bits.push(`إجازة للموظف: ${compactText(row.employee_name || row.employee || 'غير محدد', 70)}`);
    const from = formatLogDate(row.from || row.from_date);
    const to = formatLogDate(row.to || row.to_date);
    if (from || to) bits.push(`الفترة: ${from || '-'} إلى ${to || '-'}`);
    if (row.reason) bits.push(`السبب: ${compactText(row.reason, 60)}`);
  } else {
    const label = row.name || row.title || row.invoice_no || row.code || row.id || '';
    if (label) bits.push(compactText(label, 90));
  }
  return bits.filter(Boolean).join(' — ');
}

function sectionSingularLabel(sectionKey) {
  return ({
    bq_products: 'منتج',
    bq_sales: 'فاتورة بيع',
    bq_customers: 'عميل',
    bq_suppliers: 'مورد',
    bq_expenses: 'مصروف',
    bq_purchases: 'فاتورة شراء',
    bq_installments: 'قسط',
    bq_employees: 'موظف',
    bq_leaves: 'إجازة',
    bq_pur_inst: 'قسط مشتريات'
  })[sectionKey] || sectionLabel(sectionKey);
}

function inferStateChangeDescription(sectionKey, beforeValue, afterValue, failed = '') {
  const section = sectionLabel(sectionKey);
  const singular = sectionSingularLabel(sectionKey);

  if (COUNTER_STATE_KEYS?.has?.(sectionKey)) {
    return failed + `تغيير ${section} إلى ${compactText(afterValue, 30)}`;
  }
  if (!Array.isArray(beforeValue) || !Array.isArray(afterValue)) {
    return failed + `حفظ إعدادات/بيانات ${section}`;
  }

  const beforeMap = new Map(beforeValue.map((r, i) => [stableRecordKey(sectionKey, r, i), r]));
  const afterMap = new Map(afterValue.map((r, i) => [stableRecordKey(sectionKey, r, i), r]));
  let added = [];
  let removed = [];
  let updated = [];

  for (const [k, row] of afterMap.entries()) {
    if (!beforeMap.has(k)) added.push(row);
    else if (stableJson(comparableRecord(beforeMap.get(k))) !== stableJson(comparableRecord(row))) updated.push(row);
  }
  for (const [k, row] of beforeMap.entries()) {
    if (!afterMap.has(k)) removed.push(row);
  }

  if (!added.length && !removed.length && !updated.length && afterValue.length !== beforeValue.length) {
    if (afterValue.length > beforeValue.length) added = afterValue.slice(beforeValue.length);
    if (beforeValue.length > afterValue.length) removed = beforeValue.slice(afterValue.length);
  }

  const describeOne = (verb, row) => {
    const label = sectionRecordLabel(sectionKey, row);
    return failed + `${verb} ${singular}${label ? ` — ${label}` : ''}`;
  };

  if (added.length === 1 && removed.length === 0 && updated.length === 0) return describeOne('إضافة', added[0]);
  if (removed.length === 1 && added.length === 0 && updated.length === 0) return describeOne('حذف', removed[0]);
  if (updated.length === 1 && added.length === 0 && removed.length === 0) return describeOne('تعديل', updated[0]);

  if (added.length && !removed.length && !updated.length) {
    const last = added[added.length - 1];
    return failed + `إضافة ${added.length} ${singular}${added.length === 1 ? '' : 'ات'} في ${section}${last ? ` — آخر سجل: ${sectionRecordLabel(sectionKey, last)}` : ''}`;
  }
  if (removed.length && !added.length && !updated.length) return failed + `حذف ${removed.length} سجل من ${section}`;
  if (updated.length && !added.length && !removed.length) return failed + `تعديل ${updated.length} سجل في ${section}`;
  return failed + `مزامنة قسم ${section}: إضافة ${added.length} / تعديل ${updated.length} / حذف ${removed.length} — الإجمالي الآن ${afterValue.length} سجل`;
}

function frontendEventDescription(body = {}) {
  const base = compactText(body.action || 'حدث من الواجهة', 120);
  const details = body.details || {};
  const label = compactText(details.label || details.button || details.text || '', 120);
  const page = compactText(details.pageTitle || body.page || details.to || '', 80);
  const from = compactText(details.from || '', 50);
  const to = compactText(details.to || '', 50);

  // لا نسجل التنقلات العادية في سجل العمليات حتى لا تزاحم الأحداث المهمة
  if (base === 'فتح صفحة داخل الأدمن' || base === 'فتح صفحة الواجهة' || base === 'فتح صفحة داخل الواجهة') {
    return null;
  }
  if (base === 'ضغط داخل الواجهة' && label) return `ضغط على زر/عنصر: ${label}${page ? ` — الصفحة: ${page}` : ''}`;
  if (base.includes('حفظ') && label) return `${base}: ${label}`;
  if (label && !base.includes(label)) return `${base}: ${label}`;
  return base;
}

function activityDescription(req, res) {
  const method = req.method.toUpperCase();
  const pathOnly = (req.path || '').replace(/\/+$/, '');
  const parts = pathOnly.split('/').filter(Boolean);
  const failed = res.statusCode >= 400 ? 'فشل: ' : '';
  const body = req.body || {};
  if (pathOnly === '/api/auth/login' || pathOnly === '/api/admin/login') return failed + `تسجيل دخول${body.email ? ` (${compactText(body.email, 60)})` : ''}`;
  if (pathOnly === '/api/auth/register') return failed + `تسجيل مستخدم جديد${namedRecordFromBody(body)}`;
  if (pathOnly === '/api/activity/log') return failed + frontendEventDescription(body);
  if (pathOnly === '/api/admin/sync-database') return failed + 'مزامنة قاعدة البيانات ونقل بيانات الواجهة إلى PostgreSQL';
  if (pathOnly === '/api/admin/backup/restore') return failed + 'استرجاع نسخة احتياطية من ملف JSON';
  if (parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'section') {
    const key = decodeURIComponent(parts[3] || '');
    if (method === 'PUT') return inferStateChangeDescription(key, req.activityBeforeValue, body.value, failed);
    if (method === 'DELETE') return failed + `إعادة تعيين قسم ${sectionLabel(key)} إلى البيانات الافتراضية`;
  }
  if (parts[0] === 'api' && parts[1] === 'state') {
    const key = decodeURIComponent(parts[2] || '');
    if (method === 'PUT') return inferStateChangeDescription(key, req.activityBeforeValue, body.value, failed);
  }
  if (parts[0] === 'api' && parts[1] === 'users') {
    if (method === 'POST') return failed + `إضافة مستخدم جديد${namedRecordFromBody(body)}`;
    if (method === 'PUT' && parts[3] === 'password') return failed + `تغيير كلمة مرور المستخدم رقم ${compactText(parts[2] || '')}`;
    if (method === 'PUT' && parts[3] === 'toggle') return failed + `تفعيل/تعطيل المستخدم رقم ${compactText(parts[2] || '')}`;
    if (method === 'PUT') return failed + `تعديل بيانات مستخدم${namedRecordFromBody(body) || ` رقم ${compactText(parts[2] || '')}`}`;
    if (method === 'DELETE') return failed + `حذف المستخدم رقم ${compactText(parts[2] || '')}`;
  }
  const entityLabels = { products: 'منتج', sales: 'فاتورة بيع', purchases: 'فاتورة شراء', customers: 'عميل', suppliers: 'مورد', expenses: 'مصروف', installments: 'قسط', employees: 'موظف', leaves: 'إجازة', 'purchase-installments': 'قسط مشتريات', 'pur-inst': 'قسط مشتريات' };
  if (parts[0] === 'api' && entityLabels[parts[1]]) {
    const label = entityLabels[parts[1]];
    const extra = namedRecordFromBody(body);
    if (method === 'POST') return failed + `إضافة ${label}${extra}`;
    if (method === 'PUT') return failed + `تعديل ${label}${extra || ` رقم ${compactText(parts[2] || '')}`}`;
    if (method === 'DELETE') return failed + `حذف ${label} رقم ${compactText(parts[2] || '')}`;
  }
  if (method === 'POST') return failed + `تنفيذ عملية في النظام: ${pathOnly}`;
  if (method === 'PUT' || method === 'PATCH') return failed + `تعديل بيانات عبر: ${pathOnly}`;
  if (method === 'DELETE') return failed + `حذف بيانات عبر: ${pathOnly}`;
  return failed + `${method} ${pathOnly}`;
}

function activityEntity(req) {
  const parts = (req.path || '').split('/').filter(Boolean);
  if (parts[0] !== 'api') return { entity: 'system', entityId: null };
  if (parts[1] === 'admin' && parts[2] === 'section') return { entity: 'section', entityId: decodeURIComponent(parts[3] || '') || null };
  if (parts[1] === 'state') return { entity: 'state', entityId: decodeURIComponent(parts[2] || '') || null };
  if (parts[1] === 'users') return { entity: 'user', entityId: parts[2] || req.body?.email || null };
  return { entity: parts[1] || 'api', entityId: parts[2] || req.body?.id || req.body?._id || req.body?.code || null };
}

async function logActivity(entry = {}) {
  try {
    await q(
      `INSERT INTO app_activity_logs
       (action, user_email, source, page, entity, entity_id, method, path, status_code, level, details, ip, user_agent, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, NOW())`,
      [String(entry.action || 'حدث في النظام').slice(0, 500), entry.user || entry.user_email || 'system', entry.source || 'api', entry.page || null, entry.entity || null, entry.entityId || entry.entity_id || null, entry.method || null, entry.path || null, Number.isFinite(Number(entry.statusCode ?? entry.status_code)) ? Number(entry.statusCode ?? entry.status_code) : null, entry.level || 'info', JSON.stringify(jsonSafe(entry.details || {})), entry.ip || null, entry.userAgent || entry.user_agent || null]
    );
  } catch (err) { console.warn('⚠️ Activity log skipped:', err.message); }
}

function shouldAutoLog(req) {
  if (!req.path?.startsWith('/api/')) return false;
  if (req.method === 'OPTIONS') return false;
  const pathOnly = req.path.replace(/\/+$/, '');
  const ignored = new Set(['/api/health', '/api/monitor/logs', '/api/monitor/stats', '/api/activity/log']);
  if (ignored.has(pathOnly)) return false;
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method.toUpperCase());
}

async function attachActivityAutoLogger(req, res, next) {
  const startedAt = Date.now();

  // قبل تنفيذ PUT على أقسام البيانات نحفظ نسخة قديمة، حتى نقدر نكتب لوج واضح: إضافة/تعديل/حذف سجل بعينه
  try {
    const method = req.method.toUpperCase();
    const pathOnly = (req.path || '').replace(/\/+$/, '');
    const parts = pathOnly.split('/').filter(Boolean);
    let stateKey = null;
    if (method === 'PUT' && parts[0] === 'api' && parts[1] === 'state' && parts[2]) stateKey = decodeURIComponent(parts[2]);
    if (method === 'PUT' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'section' && parts[3]) stateKey = decodeURIComponent(parts[3]);
    if (stateKey && ALLOWED_STATE_KEYS?.has?.(stateKey)) {
      req.activityBeforeValue = await getAdminSectionValue(stateKey);
    }
  } catch (err) {
    req.activityBeforeValue = undefined;
  }

  res.on('finish', () => {
    if (!shouldAutoLog(req)) return;
    const { entity, entityId } = activityEntity(req);
    const user = req.user?.email || req.body?.email || req.headers['x-user-email'] || 'guest';
    logActivity({ action: activityDescription(req, res), user, source: inferActivitySource(req), page: req.headers['x-bq-page'] || req.body?.page || null, entity, entityId, method: req.method, path: req.originalUrl || req.path, statusCode: res.statusCode, level: res.statusCode >= 400 ? 'error' : 'info', details: { ...safeBodyDetails(req), beforeCount: countValueRecords(req.activityBeforeValue), durationMs: Date.now() - startedAt }, ip: clientIp(req), userAgent: req.headers['user-agent'] || '' });
  });
  next();
}

function defaultDeptForRole(role) {
  if (role === 'admin') return 'إدارة';
  if (role === 'accountant') return 'حسابات';
  if (role === 'seller') return 'مبيعات';
  return 'عام';
}

function publicUser(user) {
  return {
    id: String(user.id),
    name: user.name || user.email,
    email: user.email,
    role: user.role || 'user',
    dept: user.dept || defaultDeptForRole(user.role),
    active: user.active !== false,
    frontendAccess: user.frontend_access !== false && user.frontendAccess !== false,
    permissions: Object.keys(user.permissions || {}).length ? user.permissions : defaultPermissionsForRole(user.role),
    createdAt: user.created_at || user.createdAt || null,
    updatedAt: user.updated_at || user.updatedAt || null,
    passwordUpdatedAt: user.password_updated_at || user.passwordUpdatedAt || null,
    passwordVersion: Number(user.password_version || user.passwordVersion || 0)
  };
}


function publicDashboardUser(user) {
  const role = user.role || 'admin';
  const perms = Object.keys(user.permissions || {}).length ? user.permissions : defaultDashboardPermissionsForRole(role);
  return {
    id: String(user.id),
    name: user.name || user.email,
    email: user.email,
    role,
    dept: user.dept || 'لوحة التحكم',
    active: user.active !== false,
    permissions: perms,
    createdAt: user.created_at || user.createdAt || null,
    updatedAt: user.updated_at || user.updatedAt || null,
    passwordUpdatedAt: user.password_updated_at || user.passwordUpdatedAt || null,
    passwordVersion: Number(user.password_version || user.passwordVersion || 0)
  };
}

function isSuperDashboardUser(user) {
  return user?.role === 'super_admin' || user?.dashboardRole === 'super_admin';
}

function normalizeDashboardRole(role) {
  return ['super_admin','admin','viewer'].includes(role) ? role : 'admin';
}

function rowProduct(row) {
  const raw = rowRaw(row);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    code: row.code,
    name: row.name,
    category: row.category,
    buy_price: Number(row.buy_price || 0),
    sell_price: Number(row.sell_price || 0),
    stock_qty: Number(row.stock_qty || 0),
    notes: row.notes || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedBy: row.updated_by || raw.updatedBy || raw.updated_by || ''
  });
}

function rowSale(row) {
  const raw = rowRaw(row);
  const total = Number(row.total || raw.total || 0);
  const paid = Number(row.paid || raw.paid || 0);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    invoice_no: row.invoice_no || raw.invoice_no,
    customer_id: raw.customer_id || raw.customerId || '',
    customer_name: row.customer_name || raw.customer_name || 'زبون عام',
    user_name: raw.user_name || raw.seller_name || raw.userName || row.created_by || '',
    seller_name: raw.seller_name || raw.user_name || row.created_by || '',
    seller_email: raw.seller_email || raw.user_email || row.created_by || '',
    items: row.items || raw.items || [],
    subtotal: Number(raw.subtotal ?? total),
    tax_amount: Number(raw.tax_amount ?? 0),
    discount: Number(raw.discount ?? 0),
    total,
    payment_type: row.payment_type || raw.payment_type || 'cash',
    paid,
    remaining: Number(row.remaining ?? raw.remaining ?? (total - paid)),
    notes: row.notes || raw.notes || '',
    inv_type: raw.inv_type || (Number(raw.tax_amount || 0) > 0 ? 'tax' : 'normal'),
    date: row.date || raw.date,
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedAt: row.updated_at || raw.updatedAt || null
  });
}

function rowPurchase(row) {
  const raw = rowRaw(row);
  const total = Number(row.total || raw.total || 0);
  const paid = Number(row.paid || raw.paid || raw.paid_amt || 0);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    invoice_no: row.invoice_no || raw.invoice_no,
    supplier_id: raw.supplier_id || '',
    supplier_name: row.supplier_name || raw.supplier_name || 'مورد عام',
    items: row.items || raw.items || [],
    subtotal: Number(raw.subtotal ?? total),
    total,
    payment_type: row.payment_type || raw.payment_type || 'cash',
    paid,
    paid_amt: paid,
    remaining: Number(row.remaining ?? raw.remaining ?? (total - paid)),
    notes: row.notes || raw.notes || '',
    date: row.date || raw.date,
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedAt: row.updated_at || raw.updatedAt || null
  });
}

function rowEmployee(row) {
  const raw = rowRaw(row);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    name: row.name,
    nationality: row.nationality || '',
    role: row.role,
    salary: Number(row.salary || 0),
    housing: Number(row.housing || 0),
    transport: Number(row.transport || 0),
    other: Number(row.other_amount || raw.other || 0),
    total: Number(row.total || 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedBy: row.updated_by || raw.updatedBy || raw.updated_by || ''
  });
}

function rowCustomer(row) {
  return {
    _id: String(row.id),
    id: String(row.id),
    legacy_id: row.legacy_id || null,
    name: row.name || '',
    phone: row.phone || '',
    email: row.email || '',
    address: row.address || '',
    notes: row.notes || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    createdBy: row.created_by,
    updatedBy: row.updated_by
  };
}

function rowSupplier(row) {
  const raw = rowRaw(row);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    name: row.name || raw.name || '',
    phone: row.phone || raw.phone || '',
    email: row.email || raw.email || '',
    address: row.address || raw.address || '',
    goods: raw.goods || raw.products || raw.item_goods || '',
    total_purchases: Number(raw.total_purchases || raw.totalPurchases || 0),
    notes: row.notes || raw.notes || '',
    createdAt: row.created_at || raw.createdAt || null,
    updatedAt: row.updated_at || raw.updatedAt || null,
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedBy: row.updated_by || raw.updatedBy || raw.updated_by || ''
  });
}

function rowExpense(row) {
  const raw = rowRaw(row);
  const description = row.title || raw.description || raw.statement || raw.title || '';
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    title: description,
    description,
    statement: description,
    category: row.category || raw.category || 'عام',
    amount: Number(row.amount || raw.amount || 0),
    date: row.date || raw.date,
    notes: row.notes || raw.notes || '',
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedAt: row.updated_at || raw.updatedAt || null
  });
}

function rowInstallment(row) {
  const raw = rowRaw(row);
  const amount = Number(row.amount || raw.amount_due || raw.amount || 0);
  const paid = Number(row.paid || raw.amount_paid || raw.paid || 0);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    sale_id: raw.sale_id || raw.saleId || '',
    invoice_no: raw.invoice_no || raw.invoiceNo || '',
    customer_id: raw.customer_id || '',
    customer_name: row.customer_name || raw.customer_name || '',
    seller_name: raw.seller_name || raw.user_name || row.created_by || '',
    seller_email: raw.seller_email || raw.user_email || row.created_by || '',
    amount_due: amount,
    amount,
    amount_paid: paid,
    paid,
    remaining: Number(row.remaining ?? raw.remaining ?? (amount - paid)),
    due_date: row.due_date || raw.due_date,
    status: row.status || raw.status || 'pending',
    notes: row.notes || raw.notes || '',
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedAt: row.updated_at || raw.updatedAt || null
  });
}

function rowLeave(row) {
  const raw = rowRaw(row);
  return mergeRowData(row, {
    _id: String(row.id),
    id: String(raw.id || row.legacy_id || row.id),
    db_id: String(row.id),
    legacy_id: row.legacy_id || raw.legacy_id || null,
    employee_name: row.employee_name || raw.employee_name || raw.emp_name || '',
    employee_id: row.employee_id ? String(row.employee_id) : String(raw.employee_id || raw.emp_id || ''),
    emp_id: row.employee_id ? String(row.employee_id) : String(raw.emp_id || raw.employee_id || ''),
    from: row.from_date || raw.from || raw.from_date,
    to: row.to_date || raw.to || raw.to_date,
    leave_type: raw.leave_type || raw.type || 'no_deduction',
    type: raw.leave_type || raw.type || 'no_deduction',
    deduction_mode: raw.deduction_mode || raw.deductionMode || 'days',
    deduction_days: Number(raw.deduction_days || raw.deduct_days || 0),
    deduction_amount: Number(raw.deduction_amount || raw.deduction || 0),
    reason: row.reason || raw.reason || '',
    status: row.status || raw.status || 'pending',
    notes: row.notes || raw.notes || '',
    createdBy: row.created_by || raw.createdBy || raw.created_by || '',
    updatedAt: row.updated_at || raw.updatedAt || null
  });
}

function rowPurchaseInstallment(row) {
  return {
    _id: String(row.id),
    id: String(row.id),
    legacy_id: row.legacy_id || null,
    supplier_name: row.supplier_name || '',
    amount: Number(row.amount || 0),
    paid: Number(row.paid || 0),
    remaining: Number(row.remaining || 0),
    due_date: row.due_date,
    status: row.status || 'pending',
    notes: row.notes || '',
    createdBy: row.created_by,
    updatedAt: row.updated_at
  };
}

function rowCounter(row, fallback = 1) {
  return Number(row?.value ?? fallback);
}

const TABLES_WITH_RAW_DATA = new Set(['products','sales','purchases','employees','customers','suppliers','expenses','installments','employee_leaves','purchase_installments']);

function rawObject(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return {};
  return row;
}

function rowRaw(row) {
  return row && row.data && typeof row.data === 'object' && !Array.isArray(row.data) ? row.data : {};
}

function mergeRowData(row, normalized) {
  const raw = rowRaw(row);
  return { ...raw, ...normalized };
}

function legacyId(row, prefix = 'item') {
  return String(row?.legacy_id || row?._id || row?.id || `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`);
}

function numericId(row) {
  const n = Number(row?.id ?? row?._id);
  return Number.isInteger(n) && n > 0 ? n : null;
}

async function insertWithOptionalId(client, table, columns, values, row) {
  const finalColumns = [...columns];
  const finalValues = [...values];
  if (TABLES_WITH_RAW_DATA.has(table) && !finalColumns.includes('data')) {
    finalColumns.push('data');
    finalValues.push(JSON.stringify(rawObject(row)));
  }

  const id = numericId(row);
  if (id) {
    const allColumns = ['id', ...finalColumns];
    const placeholders = allColumns.map((_, i) => `$${i + 1}`).join(', ');
    await client.query(
      `INSERT INTO ${table} (${allColumns.join(', ')}) VALUES (${placeholders})`,
      [id, ...finalValues]
    );

    // مهم جدًا: عند إدخال id يدويًا داخل TRUNCATE/REPLACE لا تتحرك sequence تلقائيًا،
    // وبالتالي أول INSERT بدون id قد يحاول استخدام id=1 ويسبب products_pkey duplicate.
    // لذلك نعيد ضبط الـ sequence بعد أي إدخال يدوي للـ id.
    await resetSerial(client, table);
  } else {
    const placeholders = finalColumns.map((_, i) => `$${i + 1}`).join(', ');
    await client.query(
      `INSERT INTO ${table} (${finalColumns.join(', ')}) VALUES (${placeholders})`,
      finalValues
    );
  }
}

async function resetSerial(client, table) {
  await client.query(`SELECT setval(pg_get_serial_sequence('${table}', 'id'), COALESCE((SELECT MAX(id) FROM ${table}), 0) + 1, false)`);
}

async function normalizeAllSequences() {
  const tables = [
    'products',
    'sales',
    'purchases',
    'employees',
    'customers',
    'suppliers',
    'expenses',
    'installments',
    'employee_leaves',
    'purchase_installments'
  ];

  for (const table of tables) {
    try {
      await resetSerial(pool, table);
    } catch (err) {
      console.error(`⚠️ Sequence reset failed for ${table}:`, err.message);
    }
  }
}

async function getActiveSellersForRepair() {
  const result = await q(
    `SELECT id, email, name, role
     FROM app_users
     WHERE active = TRUE AND role = 'seller'
     ORDER BY id ASC`
  );
  return result.rows || [];
}

function saleHasUsefulSellerOwner(row) {
  const raw = rowRaw(row);
  const candidates = [
    row.created_by,
    raw.seller_email,
    raw.user_email,
    raw.createdBy,
    raw.created_by,
    raw.seller_name,
    raw.user_name
  ].map(v => String(v || '').trim()).filter(Boolean);

  return candidates.some(v => {
    const n = normalizeOwnerValue(v);
    return n && !['state-migration', 'system', 'migration', 'admin'].includes(n);
  });
}

async function repairLegacySalesOwners() {
  try {
    const sellers = await getActiveSellersForRepair();
    if (!sellers.length) {
      console.log('ℹ️ Legacy sales owner repair skipped: no active sellers found');
      return;
    }

    const fallbackEmail = process.env.LEGACY_SALES_OWNER_EMAIL || sellers[0].email;
    const fallbackSeller = sellers.find(s => normalizeOwnerValue(s.email) === normalizeOwnerValue(fallbackEmail)) || sellers[0];

    const result = await q(
      `SELECT * FROM sales
       ORDER BY date ASC, id ASC`
    );

    let repaired = 0;
    for (const sale of result.rows) {
      const raw = rowRaw(sale);
      const normalized = rowSale(sale);
      const candidateRecord = { ...raw, ...normalized, data: raw };

      let matchedSeller = sellers.find(seller => recordMatchesOwner(candidateRecord, seller));

      // الفواتير القديمة جدًا غالبًا لا تحتوي على seller_email أو user_name،
      // وكانت تنتقل من localStorage إلى PostgreSQL باسم admin أو state-migration.
      // في هذه الحالة نربطها بأول بائع نشط، ويمكن تغييره من env: LEGACY_SALES_OWNER_EMAIL.
      const currentOwner = normalizeOwnerValue(sale.created_by || raw.createdBy || raw.created_by || raw.seller_email || raw.user_email);
      const isLegacyOwner = !currentOwner || ['state-migration', 'system', 'migration', 'admin'].includes(currentOwner) || currentOwner.includes('admin@');
      if (!matchedSeller && isLegacyOwner) matchedSeller = fallbackSeller;

      if (!matchedSeller) continue;

      const targetEmail = matchedSeller.email;
      const targetName = matchedSeller.name || matchedSeller.email;
      const mergedRaw = {
        ...raw,
        seller_email: raw.seller_email || raw.user_email || targetEmail,
        user_email: raw.user_email || raw.seller_email || targetEmail,
        seller_name: raw.seller_name || raw.user_name || targetName,
        user_name: raw.user_name || raw.seller_name || targetName,
        createdBy: raw.createdBy || targetEmail,
        created_by: raw.created_by || targetEmail
      };

      const alreadyOwnedByTarget = normalizeOwnerValue(sale.created_by) === normalizeOwnerValue(targetEmail)
        && normalizeOwnerValue(raw.seller_email || raw.user_email) === normalizeOwnerValue(targetEmail);

      if (alreadyOwnedByTarget) continue;

      await q(
        `UPDATE sales
         SET created_by = $1,
             data = COALESCE(data, '{}'::jsonb) || $2::jsonb,
             updated_at = COALESCE(updated_at, NOW())
         WHERE id = $3`,
        [targetEmail, JSON.stringify(mergedRaw), sale.id]
      );
      repaired += 1;
    }

    if (repaired > 0) {
      const freshSales = await getAdminSectionValue('bq_sales');
      await mirrorSectionState('bq_sales', freshSales, 'legacy-sales-owner-repair');
      console.log(`✅ Legacy sales owner repair completed: ${repaired} invoice(s) linked to sellers`);
    } else {
      console.log('✅ Legacy sales owner repair checked: no invoices needed repair');
    }
  } catch (err) {
    console.error('⚠️ Legacy sales owner repair error:', err.message);
  }
}

async function connectDB() {
  try {
    await q('SELECT NOW()');
    console.log('✅ Connected to PostgreSQL');

    await createSchema();
    await seedDefaultUsers();
    await seedDashboardUsers();
    await forceDashboardBootstrapResetOnce();
    await cleanupDashboardFrontendLeakage();
    await separateDashboardAndFrontendUsers();
    await seedDefaultState();
    await seedDefaultProductsTable();
    await migrateExistingAppStateToRelationalTables();
    await syncAllSectionsToState('system');
    await normalizeAllSequences();
    await repairLegacySalesOwners();
  } catch (err) {
    console.error('❌ PostgreSQL connection/setup error:', err);
    process.exit(1);
  }
}

async function createSchema() {
  await q(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'seller',
      dept TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;`);
  await q(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_updated_by TEXT;`);
  await q(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_version INTEGER NOT NULL DEFAULT 0;`);
  await q(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS frontend_access BOOLEAN NOT NULL DEFAULT TRUE;`);


  await q(`
    CREATE TABLE IF NOT EXISTS dashboard_users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      dept TEXT DEFAULT 'لوحة التحكم',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT,
      password_updated_at TIMESTAMPTZ,
      password_updated_by TEXT,
      password_version INTEGER NOT NULL DEFAULT 0
    );
  `);

  await q(`ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;`);
  await q(`ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS password_updated_by TEXT;`);
  await q(`ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS password_version INTEGER NOT NULL DEFAULT 0;`);
  await q(`CREATE INDEX IF NOT EXISTS idx_dashboard_users_role ON dashboard_users(role);`);

  await q(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by TEXT
    );
  `);


  await q(`
    CREATE TABLE IF NOT EXISTS app_activity_logs (
      id BIGSERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      user_email TEXT DEFAULT 'system',
      source TEXT DEFAULT 'api',
      page TEXT,
      entity TEXT,
      entity_id TEXT,
      method TEXT,
      path TEXT,
      status_code INTEGER,
      level TEXT NOT NULL DEFAULT 'info',
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      category TEXT DEFAULT 'أخرى',
      buy_price NUMERIC(14,2) NOT NULL DEFAULT 0,
      sell_price NUMERIC(14,2) NOT NULL DEFAULT 0,
      stock_qty INTEGER NOT NULL DEFAULT 0,
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS sales (
      id BIGSERIAL PRIMARY KEY,
      invoice_no TEXT NOT NULL UNIQUE,
      customer_name TEXT NOT NULL DEFAULT 'زبون عام',
      items JSONB NOT NULL DEFAULT '[]'::jsonb,
      total NUMERIC(14,2) NOT NULL DEFAULT 0,
      payment_type TEXT NOT NULL DEFAULT 'cash',
      paid NUMERIC(14,2) NOT NULL DEFAULT 0,
      remaining NUMERIC(14,2) NOT NULL DEFAULT 0,
      notes TEXT DEFAULT '',
      date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_by TEXT,
      updated_at TIMESTAMPTZ
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS purchases (
      id BIGSERIAL PRIMARY KEY,
      invoice_no TEXT NOT NULL UNIQUE,
      supplier_name TEXT NOT NULL DEFAULT 'مورد عام',
      items JSONB NOT NULL DEFAULT '[]'::jsonb,
      total NUMERIC(14,2) NOT NULL DEFAULT 0,
      payment_type TEXT NOT NULL DEFAULT 'cash',
      paid NUMERIC(14,2) NOT NULL DEFAULT 0,
      remaining NUMERIC(14,2) NOT NULL DEFAULT 0,
      notes TEXT DEFAULT '',
      date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_by TEXT,
      updated_at TIMESTAMPTZ
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS employees (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT,
      name TEXT NOT NULL,
      nationality TEXT DEFAULT '',
      role TEXT NOT NULL,
      salary NUMERIC(14,2) NOT NULL DEFAULT 0,
      housing NUMERIC(14,2) NOT NULL DEFAULT 0,
      transport NUMERIC(14,2) NOT NULL DEFAULT 0,
      other_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      total NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`ALTER TABLE products ADD COLUMN IF NOT EXISTS legacy_id TEXT;`);
  await q(`ALTER TABLE sales ADD COLUMN IF NOT EXISTS legacy_id TEXT;`);
  await q(`ALTER TABLE purchases ADD COLUMN IF NOT EXISTS legacy_id TEXT;`);
  await q(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS legacy_id TEXT;`);
  await q(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS updated_by TEXT;`);
  await q(`ALTER TABLE products ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE sales ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE purchases ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);

  await q(`
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS suppliers (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS expenses (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      title TEXT NOT NULL,
      category TEXT DEFAULT 'عام',
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS installments (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      customer_name TEXT NOT NULL DEFAULT '',
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      paid NUMERIC(14,2) NOT NULL DEFAULT 0,
      remaining NUMERIC(14,2) NOT NULL DEFAULT 0,
      due_date DATE,
      status TEXT NOT NULL DEFAULT 'pending',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS employee_leaves (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      employee_name TEXT NOT NULL DEFAULT '',
      employee_id BIGINT,
      from_date DATE,
      to_date DATE,
      reason TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS purchase_installments (
      id BIGSERIAL PRIMARY KEY,
      legacy_id TEXT UNIQUE,
      supplier_name TEXT NOT NULL DEFAULT '',
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      paid NUMERIC(14,2) NOT NULL DEFAULT 0,
      remaining NUMERIC(14,2) NOT NULL DEFAULT 0,
      due_date DATE,
      status TEXT NOT NULL DEFAULT 'pending',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS app_counters (
      key TEXT PRIMARY KEY,
      value BIGINT NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by TEXT
    );
  `);

  await q(`CREATE UNIQUE INDEX IF NOT EXISTS idx_products_legacy_id ON products(legacy_id) WHERE legacy_id IS NOT NULL;`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_legacy_id ON sales(legacy_id) WHERE legacy_id IS NOT NULL;`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS idx_purchases_legacy_id ON purchases(legacy_id) WHERE legacy_id IS NOT NULL;`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_legacy_id ON employees(legacy_id) WHERE legacy_id IS NOT NULL;`);

  await q(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE suppliers ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE installments ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE employee_leaves ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await q(`ALTER TABLE purchase_installments ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;`);

  await q('CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(date DESC);');
  await q('CREATE INDEX IF NOT EXISTS idx_purchases_date ON purchases(date DESC);');
  await q('CREATE INDEX IF NOT EXISTS idx_app_users_role ON app_users(role);');
  await q('CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON app_activity_logs(created_at DESC);');
  await q('CREATE INDEX IF NOT EXISTS idx_activity_logs_source ON app_activity_logs(source);');
  await q('CREATE INDEX IF NOT EXISTS idx_activity_logs_entity ON app_activity_logs(entity);');
  console.log('✅ PostgreSQL schema ready');
}

async function seedDefaultUsers() {
  try {
    for (const user of DEFAULT_USERS) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      await q(
        `INSERT INTO app_users (email, password, name, role, dept, active, permissions, frontend_access, created_at)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6::jsonb, TRUE, NOW())
         ON CONFLICT (email) DO NOTHING`,
        [user.email, hashedPassword, user.name, user.role, user.dept || defaultDeptForRole(user.role), JSON.stringify(defaultPermissionsForRole(user.role))]
      );
      await q(
        `UPDATE app_users SET permissions = $1::jsonb WHERE email = $2 AND (permissions IS NULL OR permissions = '{}'::jsonb)`,
        [JSON.stringify(defaultPermissionsForRole(user.role)), user.email]
      );
    }
    console.log('✅ Default users ready (existing passwords are preserved)');
  } catch (err) {
    console.error('⚠️ Default users seed error:', err);
  }
}


async function updateUserPasswordPersistently({ id, email, newPassword, actorEmail }) {
  const finalPassword = String(newPassword || '').trim();
  if (!finalPassword) {
    const err = new Error('New password required');
    err.status = 400;
    throw err;
  }
  if (!id && !email) {
    const err = new Error('User id or email required');
    err.status = 400;
    throw err;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = id
      ? await client.query('SELECT id, email, name, role FROM app_users WHERE id = $1 FOR UPDATE', [id])
      : await client.query('SELECT id, email, name, role FROM app_users WHERE LOWER(email) = LOWER($1) FOR UPDATE', [email]);

    const user = found.rows[0];
    if (!user) {
      const err = new Error('User not found');
      err.status = 404;
      throw err;
    }

    const hashedPassword = await bcrypt.hash(finalPassword, 10);
    const updated = await client.query(
      `UPDATE app_users
       SET password = $1,
           updated_at = NOW(),
           updated_by = $2,
           password_updated_at = NOW(),
           password_updated_by = $2,
           password_version = COALESCE(password_version, 0) + 1
       WHERE id = $3
       RETURNING id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_updated_by, password_version`,
      [hashedPassword, actorEmail || 'system', user.id]
    );
    await client.query('COMMIT');
    return publicUser(updated.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}



async function ensureDashboardRecoveryAccess() {
  const bootstrapEmail = (process.env.DASHBOARD_BOOTSTRAP_EMAIL || 'admin@binqazamel.ae').toLowerCase();
  const bootstrapPassword = process.env.DASHBOARD_BOOTSTRAP_PASSWORD || '1234';
  try {
    const activeSupers = await q(
      `SELECT COUNT(*)::int AS count
       FROM dashboard_users
       WHERE active = TRUE AND role = 'super_admin'`
    );

    // Safety net: if there is no active dashboard owner, create one.
    // This prevents locking yourself out without re-creating deleted users unnecessarily.
    if ((activeSupers.rows[0]?.count || 0) === 0) {
      const hashedPassword = await bcrypt.hash(bootstrapPassword, 10);
      await q(
        `INSERT INTO dashboard_users (email, password, name, role, dept, active, permissions, created_at, created_by, password_updated_at, password_updated_by, password_version)
         VALUES ($1, $2, $3, 'super_admin', 'لوحة التحكم', TRUE, $4::jsonb, NOW(), 'recovery', NOW(), 'recovery', 1)
         ON CONFLICT (email) DO UPDATE SET
           password = EXCLUDED.password,
           role = 'super_admin',
           active = TRUE,
           permissions = EXCLUDED.permissions,
           updated_at = NOW(),
           updated_by = 'recovery',
           password_updated_at = NOW(),
           password_updated_by = 'recovery',
           password_version = COALESCE(dashboard_users.password_version, 0) + 1`,
        [bootstrapEmail, hashedPassword, 'مالك لوحة التحكم', JSON.stringify(defaultDashboardPermissionsForRole('super_admin'))]
      );
      console.log(`✅ Dashboard recovery owner is ready: ${bootstrapEmail}`);
      return;
    }

    // One-time repair for V18 migrations:
    // Some dashboard users were copied from app_users with an old password hash,
    // so admin@binqazamel.ae / 1234 stopped working immediately after the split.
    // We reset only untouched migrated/system bootstrap accounts once, then never overwrite again.
    if (process.env.DASHBOARD_DISABLE_AUTO_REPAIR !== 'true') {
      const target = await q(
        `SELECT id, email, created_by, password_version, password_updated_at
         FROM dashboard_users
         WHERE LOWER(email) = LOWER($1)
           AND COALESCE(password_version, 0) = 0
           AND password_updated_at IS NULL
           AND COALESCE(created_by, '') IN ('migration', 'system')
         LIMIT 1`,
        [bootstrapEmail]
      );

      if (target.rows[0]) {
        const hashedPassword = await bcrypt.hash(bootstrapPassword, 10);
        await q(
          `UPDATE dashboard_users
           SET password = $1,
               role = 'super_admin',
               active = TRUE,
               permissions = $2::jsonb,
               updated_at = NOW(),
               updated_by = 'startup-password-repair',
               password_updated_at = NOW(),
               password_updated_by = 'startup-password-repair',
               password_version = 1
           WHERE id = $3`,
          [hashedPassword, JSON.stringify(defaultDashboardPermissionsForRole('super_admin')), target.rows[0].id]
        );
        console.log(`✅ Dashboard bootstrap password repaired once for ${bootstrapEmail}`);
      }
    }
  } catch (err) {
    console.error('⚠️ Dashboard recovery access check failed:', err);
  }
}


async function forceDashboardBootstrapResetOnce() {
  const bootstrapEmail = (process.env.DASHBOARD_BOOTSTRAP_EMAIL || 'admin@binqazamel.ae').toLowerCase();
  const bootstrapPassword = process.env.DASHBOARD_BOOTSTRAP_PASSWORD || '1234';
  const skipReset = process.env.DASHBOARD_SKIP_V22_LOGIN_RESET === 'true';
  const resetKey = `dashboard_login_recovery_v22_${bootstrapEmail}`;

  if (skipReset) {
    console.log('ℹ️ Dashboard V22 login recovery skipped by env DASHBOARD_SKIP_V22_LOGIN_RESET=true');
    return;
  }

  try {
    const alreadyDone = await q('SELECT key FROM app_state WHERE key = $1 LIMIT 1', [resetKey]);
    if (alreadyDone.rows[0]) {
      console.log(`✅ Dashboard V22 login recovery already applied for ${bootstrapEmail}`);
      return;
    }

    const hashedPassword = await bcrypt.hash(bootstrapPassword, 10);
    const permissions = JSON.stringify(defaultDashboardPermissionsForRole('super_admin'));
    const existing = await q('SELECT id FROM dashboard_users WHERE LOWER(email) = LOWER($1) LIMIT 1', [bootstrapEmail]);

    if (existing.rows[0]) {
      await q(
        `UPDATE dashboard_users
         SET password = $1,
             name = COALESCE(NULLIF(name, ''), 'مالك لوحة التحكم'),
             role = 'super_admin',
             dept = COALESCE(NULLIF(dept, ''), 'لوحة التحكم'),
             active = TRUE,
             permissions = $2::jsonb,
             updated_at = NOW(),
             updated_by = 'v22-login-recovery',
             password_updated_at = NOW(),
             password_updated_by = 'v22-login-recovery',
             password_version = COALESCE(password_version, 0) + 1
         WHERE id = $3`,
        [hashedPassword, permissions, existing.rows[0].id]
      );
    } else {
      await q(
        `INSERT INTO dashboard_users (email, password, name, role, dept, active, permissions, created_at, created_by, password_updated_at, password_updated_by, password_version)
         VALUES ($1, $2, 'مالك لوحة التحكم', 'super_admin', 'لوحة التحكم', TRUE, $3::jsonb, NOW(), 'v22-login-recovery', NOW(), 'v22-login-recovery', 1)`,
        [bootstrapEmail, hashedPassword, permissions]
      );
    }

    await q(
      `INSERT INTO app_state (key, value, created_at, updated_at, updated_by)
       VALUES ($1, $2::jsonb, NOW(), NOW(), 'v22-login-recovery')
       ON CONFLICT (key) DO NOTHING`,
      [resetKey, JSON.stringify({ email: bootstrapEmail, appliedAt: new Date().toISOString(), note: 'One-time dashboard login recovery. Change the password from Admin Access after login.' })]
    );

    console.log(`✅ Dashboard login recovered once: ${bootstrapEmail} / ${bootstrapPassword}`);
  } catch (err) {
    console.error('⚠️ Dashboard V22 login recovery failed:', err.message);
  }
}

async function seedDashboardUsers() {
  try {
    const existing = await q('SELECT COUNT(*)::int AS count FROM dashboard_users');
    if ((existing.rows[0]?.count || 0) > 0) {
      await ensureDashboardRecoveryAccess();
      await cleanupDashboardFrontendLeakage();
      console.log('✅ Dashboard access users ready (no frontend-user migration)');
      return;
    }

    // لا ننقل مديري الواجهة إلى dashboard_users نهائياً.
    // الداشبورد له أكسيس مستقل فقط.
    for (const user of DEFAULT_DASHBOARD_USERS) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      await q(
        `INSERT INTO dashboard_users (email, password, name, role, dept, active, permissions, created_at, created_by)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6::jsonb, NOW(), 'system')
         ON CONFLICT (email) DO NOTHING`,
        [user.email, hashedPassword, user.name, normalizeDashboardRole(user.role), user.dept || 'لوحة التحكم', JSON.stringify(defaultDashboardPermissionsForRole(user.role))]
      );
    }

    await cleanupDashboardFrontendLeakage();
    console.log('✅ Dashboard access default users ready');
  } catch (err) {
    console.error('⚠️ Dashboard access seed error:', err);
  }
}

async function cleanupDashboardFrontendLeakage() {
  try {
    const managerEmail = (process.env.FRONTEND_MANAGER_EMAIL || 'manager@binqazamel.ae').toLowerCase();
    const deleted = await q(
      `DELETE FROM dashboard_users
       WHERE LOWER(email) = LOWER($1)
       RETURNING id, email`,
      [managerEmail]
    );
    if (deleted.rowCount) console.log(`✅ Removed frontend manager from dashboard access: ${managerEmail}`);
  } catch (err) {
    console.error('⚠️ Dashboard/frontend leakage cleanup failed:', err.message);
  }
}

async function separateDashboardAndFrontendUsers() {
  try {
    // أي إيميل موجود كأكسيس داشبورد يتم فصله عن شاشة الواجهة تلقائيًا.
    await q(`
      UPDATE app_users au
      SET frontend_access = FALSE,
          updated_at = NOW(),
          updated_by = 'separate-dashboard-users'
      WHERE EXISTS (
        SELECT 1 FROM dashboard_users du WHERE LOWER(du.email) = LOWER(au.email)
      )
    `);

    // مهم: لا نعيد إنشاء manager@binqazamel.ae أو أي مدير واجهة بعد الحذف.
    // لو عايز تعمل مدير واجهة، اعمله من صفحة "مستخدمو الواجهة" فقط.
    // ولو محتاج Seed اضطراري، فعّل هذا المتغير في .env:
    // SEED_FRONTEND_MANAGER=true
    if (process.env.SEED_FRONTEND_MANAGER !== 'true') {
      console.log('✅ Frontend manager auto-seed disabled; deleted frontend users will not return');
      return;
    }

    const managerEmail = process.env.FRONTEND_MANAGER_EMAIL || 'manager@binqazamel.ae';
    const managerPassword = process.env.FRONTEND_MANAGER_PASSWORD || '4444';
    const hasFrontendManager = await q(`
      SELECT COUNT(*)::int AS count
      FROM app_users
      WHERE active = TRUE
        AND COALESCE(frontend_access, TRUE) = TRUE
        AND role = 'admin'
    `);

    if ((hasFrontendManager.rows[0]?.count || 0) === 0) {
      const hashedPassword = await bcrypt.hash(managerPassword, 10);
      await q(
        `INSERT INTO app_users (email, password, name, role, dept, active, permissions, frontend_access, created_at, created_by)
         VALUES ($1, $2, 'المدير العام', 'admin', 'إدارة', TRUE, $3::jsonb, TRUE, NOW(), 'frontend-seed')
         ON CONFLICT (email) DO NOTHING`,
        [managerEmail, hashedPassword, JSON.stringify(defaultPermissionsForRole('admin'))]
      );
      console.log(`✅ Frontend manager access is ready: ${managerEmail}`);
    }
  } catch (err) {
    console.error('⚠️ Dashboard/frontend user separation failed:', err.message);
  }
}

async function updateDashboardPasswordPersistently({ id, email, newPassword, actorEmail = 'system' }) {
  if (!newPassword || String(newPassword).length < 3) {
    const e = new Error('New password must be at least 3 characters');
    e.status = 400;
    throw e;
  }
  const found = id
    ? await q('SELECT id, email, name, role FROM dashboard_users WHERE id = $1', [id])
    : await q('SELECT id, email, name, role FROM dashboard_users WHERE LOWER(email) = LOWER($1)', [email]);
  const user = found.rows[0];
  if (!user) {
    const e = new Error('Dashboard access user not found');
    e.status = 404;
    throw e;
  }
  const hashedPassword = await bcrypt.hash(String(newPassword), 10);
  const result = await q(
    `UPDATE dashboard_users
     SET password = $1,
         password_updated_at = NOW(),
         password_updated_by = $2,
         password_version = COALESCE(password_version, 0) + 1,
         updated_at = NOW(),
         updated_by = $2
     WHERE id = $3
     RETURNING id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_version`,
    [hashedPassword, actorEmail, user.id]
  );
  return publicDashboardUser(result.rows[0]);
}

async function seedDefaultState() {
  try {
    for (const [key, value] of Object.entries(DEFAULT_STATE)) {
      await q(
        `INSERT INTO app_state (key, value, created_at, updated_at)
         VALUES ($1, $2::jsonb, NOW(), NOW())
         ON CONFLICT (key) DO NOTHING`,
        [key, JSON.stringify(value)]
      );
    }
    console.log('✅ App state ready');
  } catch (err) {
    console.error('⚠️ App state seed error:', err);
  }
}

async function seedDefaultProductsTable() {
  try {
    for (const product of DEFAULT_PRODUCTS) {
      await q(
        `INSERT INTO products (code, name, category, buy_price, sell_price, stock_qty, notes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT (code) DO NOTHING`,
        [product.code, product.name, product.category, product.buy_price, product.sell_price, product.stock_qty, product.notes]
      );
    }
    console.log('✅ Default products ready');
  } catch (err) {
    console.error('⚠️ Default products seed error:', err);
  }
}

async function migrateExistingAppStateToRelationalTables() {
  try {
    const rows = await q('SELECT key, value FROM app_state');
    const state = Object.fromEntries(rows.rows.map(row => [row.key, row.value]));
    const userEmail = 'state-migration';

    for (const key of Object.keys(DEFAULT_STATE)) {
      const value = state[key];
      if (value === undefined || value === null) continue;

      if (key === 'bq_inv_counter' || key === 'bq_qt_counter') {
        await q(
          `INSERT INTO app_counters (key, value, created_at, updated_at, updated_by)
           VALUES ($1, $2, NOW(), NOW(), $3)
           ON CONFLICT (key) DO NOTHING`,
          [key, Number(value || DEFAULT_STATE[key] || 1), userEmail]
        );
        continue;
      }

      if (!Array.isArray(value) || !value.length) continue;
      await mergeSectionRowsFromState(key, value, userEmail);
    }
    console.log('✅ Existing app_state data migrated to relational tables');
  } catch (err) {
    console.error('⚠️ app_state migration error:', err);
  }
}

async function mergeSectionRowsFromState(key, value, userEmail) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const row of value) {
      if (!row || typeof row !== 'object') continue;
      const lid = legacyId(row, key);

      if (key === 'bq_products') {
        const code = String(row.code || lid);
        const name = String(row.name || row.title || code);
        await client.query(
          `INSERT INTO products (legacy_id, code, name, category, buy_price, sell_price, stock_qty, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
           ON CONFLICT (code) DO NOTHING`,
          [lid, code, name, row.category || 'أخرى', Number(row.buy_price || 0), Number(row.sell_price || 0), Number(row.stock_qty || 0), row.notes || '', userEmail]
        );
      } else if (key === 'bq_customers') {
        if (!row.name) continue;
        await client.query(
          `INSERT INTO customers (legacy_id, name, phone, email, address, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, row.name, row.phone || '', row.email || '', row.address || '', row.notes || '', userEmail]
        );
      } else if (key === 'bq_suppliers') {
        if (!row.name) continue;
        await client.query(
          `INSERT INTO suppliers (legacy_id, name, phone, email, address, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, row.name, row.phone || '', row.email || '', row.address || '', row.notes || '', userEmail]
        );
      } else if (key === 'bq_expenses') {
        const title = row.title || row.name || row.category || 'مصروف';
        await client.query(
          `INSERT INTO expenses (legacy_id, title, category, amount, date, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, NOW()), $6, NOW(), $7)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, title, row.category || 'عام', Number(row.amount || 0), row.date || null, row.notes || '', userEmail]
        );
      } else if (key === 'bq_installments') {
        const amount = Number(row.amount || row.total || 0);
        const paid = Number(row.paid || 0);
        await client.query(
          `INSERT INTO installments (legacy_id, customer_name, amount, paid, remaining, due_date, status, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6::date, $7, $8, NOW(), $9)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, row.customer_name || row.customer || '', amount, paid, Number(row.remaining ?? (amount - paid)), row.due_date || null, row.status || 'pending', row.notes || '', userEmail]
        );
      } else if (key === 'bq_leaves') {
        await client.query(
          `INSERT INTO employee_leaves (legacy_id, employee_name, employee_id, from_date, to_date, reason, status, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4::date, $5::date, $6, $7, $8, NOW(), $9)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, row.employee_name || row.employee || '', numericId({id: row.employee_id}) || null, row.from || row.from_date || null, row.to || row.to_date || null, row.reason || '', row.status || 'pending', row.notes || '', userEmail]
        );
      } else if (key === 'bq_pur_inst') {
        const amount = Number(row.amount || row.total || 0);
        const paid = Number(row.paid || 0);
        await client.query(
          `INSERT INTO purchase_installments (legacy_id, supplier_name, amount, paid, remaining, due_date, status, notes, created_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6::date, $7, $8, NOW(), $9)
           ON CONFLICT (legacy_id) DO NOTHING`,
          [lid, row.supplier_name || row.supplier || '', amount, paid, Number(row.remaining ?? (amount - paid)), row.due_date || null, row.status || 'pending', row.notes || '', userEmail]
        );
      }
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function syncAllSectionsToState(userEmail = 'system') {
  try {
    for (const key of Object.keys(DEFAULT_STATE)) {
      const value = await getAdminSectionValue(key);
      await mirrorSectionState(key, value, userEmail);
    }
    console.log('✅ app_state compatibility mirror synced from database tables');
  } catch (err) {
    console.error('⚠️ app_state sync error:', err);
  }
}

// ═══════════════════════════════════════
// Authentication Middleware
// ═══════════════════════════════════════
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}


function optionalAuthenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next();
  try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  next();
}

async function requireAdmin(req, res) {
  if (req.user?.role !== 'admin') {
    res.status(403).json({ error: 'Admin only' });
    return false;
  }

  // Dashboard access permissions are independent from frontend users.
  // super_admin can do everything. Other dashboard roles are limited by their permissions JSON.
  if (req.user?.scope === 'dashboard' && req.user.dashboardRole !== 'super_admin') {
    const url = req.originalUrl || req.path || '';
    const perms = req.user.permissions || {};
    let required = 'overview';
    if (url.includes('/admin-access') || url.includes('/users')) required = 'manageUsers';
    else if (url.includes('/backup')) required = 'backup';
    else if (url.includes('/monitor')) required = 'monitor';
    else if (url.includes('/admin/section') || url.includes('/admin/sections') || url.includes('/state/') || url.includes('/state/all') || url.includes('/admin/sync')) required = 'dataControl';

    if (!perms[required]) {
      res.status(403).json({ error: `Permission denied: ${required}` });
      return false;
    }
  }

  return true;
}

// ═══════════════════════════════════════
// AUTH ENDPOINTS
// ═══════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await q(`
      SELECT * FROM app_users
      WHERE LOWER(email) = LOWER($1)
        AND COALESCE(frontend_access, TRUE) = TRUE
      LIMIT 1`, [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.active === false) return res.status(403).json({ error: 'User is disabled' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: String(user.id), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.json({ token, user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Dashboard login route. This is intentionally separate from frontend users.
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await q('SELECT * FROM dashboard_users WHERE LOWER(email) = LOWER($1) LIMIT 1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid dashboard credentials' });
    if (user.active === false) return res.status(403).json({ error: 'Dashboard access is disabled' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid dashboard credentials' });

    const publicUserData = publicDashboardUser(user);
    const token = jwt.sign(
      {
        id: String(user.id),
        email: user.email,
        role: 'admin',
        scope: 'dashboard',
        dashboardRole: publicUserData.role,
        permissions: publicUserData.permissions
      },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.json({ token, user: { ...publicUserData, scope: 'dashboard' } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/register', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { email, password, name, role, dept, permissions, active } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await q(
      `INSERT INTO app_users (email, password, name, role, dept, active, permissions, frontend_access, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, TRUE, NOW(), $8)
       RETURNING *`,
      [email, hashedPassword, name || email, role || 'user', dept || defaultDeptForRole(role), active !== false, JSON.stringify(permissions || defaultPermissionsForRole(role || 'user')), req.user.email]
    );
    res.json(publicUser(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════
// DASHBOARD ACCESS USERS
// These accounts are ONLY for /admin dashboard access and are independent from frontend users.
// ═══════════════════════════════════════
app.get('/api/admin-access', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const result = await q(
      `SELECT id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_version
       FROM dashboard_users
       ORDER BY role ASC, created_at DESC, id DESC`
    );
    res.json(result.rows.map(publicDashboardUser));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin-access', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { email, password, name, role, dept, active, permissions } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const normalizedRole = normalizeDashboardRole(role);
    const hashedPassword = await bcrypt.hash(String(password), 10);
    const result = await q(
      `INSERT INTO dashboard_users (email, password, name, role, dept, active, permissions, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW(), $8)
       RETURNING id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_version`,
      [email, hashedPassword, name || email, normalizedRole, dept || 'لوحة التحكم', active !== false, JSON.stringify(permissions || defaultDashboardPermissionsForRole(normalizedRole)), req.user.email]
    );
    res.json(publicDashboardUser(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Dashboard access email already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin-access/:id/password', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const updatedUser = await updateDashboardPasswordPersistently({
      id: req.params.id,
      newPassword: req.body?.newPassword || req.body?.password,
      actorEmail: req.user.email
    });
    res.json({ ok: true, message: 'Dashboard password saved to PostgreSQL successfully', user: updatedUser });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/api/admin-access/password', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const updatedUser = await updateDashboardPasswordPersistently({
      id: req.body?.id,
      email: req.body?.email,
      newPassword: req.body?.newPassword || req.body?.password,
      actorEmail: req.user.email
    });
    res.json({ ok: true, message: 'Dashboard password saved to PostgreSQL successfully', user: updatedUser });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.put('/api/admin-access/:id/toggle', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const found = await q('SELECT id, active, role, email FROM dashboard_users WHERE id = $1', [req.params.id]);
    const user = found.rows[0];
    if (!user) return res.status(404).json({ error: 'Dashboard access user not found' });

    if (user.active !== false && user.role === 'super_admin') {
      const activeAdmins = await q(`SELECT COUNT(*)::int AS count FROM dashboard_users WHERE active = TRUE AND role = 'super_admin'`);
      if ((activeAdmins.rows[0]?.count || 0) <= 1) {
        return res.status(400).json({ error: 'Cannot disable the last active super admin' });
      }
    }

    const active = user.active === false;
    const result = await q(
      `UPDATE dashboard_users SET active = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3
       RETURNING id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_version`,
      [active, req.user.email, req.params.id]
    );
    res.json({ ok: true, user: publicDashboardUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin-access/:id', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const found = await q('SELECT id, role, active, email FROM dashboard_users WHERE id = $1', [req.params.id]);
    const user = found.rows[0];
    if (!user) return res.status(404).json({ error: 'Dashboard access user not found' });

    if (String(req.user.id) === String(user.id)) {
      return res.status(400).json({ error: 'You cannot delete the dashboard account you are currently using' });
    }

    if (user.active !== false && user.role === 'super_admin') {
      const activeAdmins = await q(`SELECT COUNT(*)::int AS count FROM dashboard_users WHERE active = TRUE AND role = 'super_admin'`);
      if ((activeAdmins.rows[0]?.count || 0) <= 1) {
        return res.status(400).json({ error: 'Cannot delete the last active super admin' });
      }
    }

    const result = await q('DELETE FROM dashboard_users WHERE id = $1', [req.params.id]);
    res.json({ ok: true, deletedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin-access/:id', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id } = req.params;
    const { name, email, role, dept, active, permissions } = req.body || {};
    const normalizedRole = normalizeDashboardRole(role || 'admin');

    if (typeof active === 'boolean' && active === false) {
      const target = await q('SELECT id, role, active FROM dashboard_users WHERE id = $1', [id]);
      if (target.rows[0]?.role === 'super_admin' && target.rows[0]?.active !== false) {
        const activeAdmins = await q(`SELECT COUNT(*)::int AS count FROM dashboard_users WHERE active = TRUE AND role = 'super_admin'`);
        if ((activeAdmins.rows[0]?.count || 0) <= 1) return res.status(400).json({ error: 'Cannot disable the last active super admin' });
      }
    }

    const result = await q(
      `UPDATE dashboard_users
       SET name = COALESCE($1, name),
           email = COALESCE($2, email),
           role = COALESCE($3, role),
           dept = COALESCE($4, dept),
           active = COALESCE($5, active),
           permissions = COALESCE($6::jsonb, permissions),
           updated_at = NOW(),
           updated_by = $7
       WHERE id = $8
       RETURNING id, email, name, role, dept, active, permissions, created_at, updated_at, password_updated_at, password_version`,
      [name || null, email || null, normalizedRole, dept || 'لوحة التحكم', typeof active === 'boolean' ? active : null, permissions ? JSON.stringify(permissions) : null, req.user.email, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Dashboard access user not found' });

    const passwordToSave = req.body?.newPassword || req.body?.password;
    if (passwordToSave) {
      const updatedWithPassword = await updateDashboardPasswordPersistently({ id, newPassword: passwordToSave, actorEmail: req.user.email });
      return res.json(updatedWithPassword);
    }
    res.json(publicDashboardUser(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Dashboard access email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// ═══════════════════════════════════════
// STATE ENDPOINTS
// All frontend state is now loaded from PostgreSQL relational tables.
// app_state remains only a compatibility mirror for older frontend screens.
// ═══════════════════════════════════════
app.get('/api/state/all', authenticate, async (req, res) => {
  try {
    const state = await getStateMap();
    res.json({ state });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/state/:key', authenticate, async (req, res) => {
  try {
    const { key } = req.params;
    if (!ALLOWED_STATE_KEYS.has(key)) return res.status(400).json({ error: 'Invalid state key' });
    const value = await getAdminSectionValue(key);
    res.json({ key, value });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/state/:key', authenticate, async (req, res) => {
  try {
    const { key } = req.params;
    if (!ALLOWED_STATE_KEYS.has(key)) return res.status(400).json({ error: 'Invalid state key' });
    const { value } = req.body;
    const fresh = await replaceTableBackedSection(key, value, req.user.email);
    res.json({ ok: true, key, value: fresh });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// ADMIN DASHBOARD ENDPOINTS
// ═══════════════════════════════════════
app.get('/api/login-users', async (req, res) => {
  try {
    const result = await q(
      `SELECT id, email, name, role, dept, active, permissions, frontend_access, created_at, updated_at
       FROM app_users
       WHERE active = TRUE
         AND COALESCE(frontend_access, TRUE) = TRUE
         AND role = ANY($1)
         AND NOT EXISTS (SELECT 1 FROM dashboard_users du WHERE LOWER(du.email) = LOWER(app_users.email))
       ORDER BY role ASC, name ASC`,
      [['admin', 'accountant', 'seller']]
    );
    res.json({ users: result.rows.map(publicUser) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function getStateMap() {
  const state = {};
  for (const key of Object.keys(DEFAULT_STATE)) {
    state[key] = await getAdminSectionValue(key);
  }
  return state;
}

app.get('/api/users', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const result = await q(
      `SELECT id, email, name, role, dept, active, permissions, frontend_access, created_at, updated_at
       FROM app_users
       WHERE COALESCE(frontend_access, TRUE) = TRUE
         AND NOT EXISTS (SELECT 1 FROM dashboard_users du WHERE LOWER(du.email) = LOWER(app_users.email))
       ORDER BY created_at DESC, id DESC`
    );
    res.json(result.rows.map(publicUser));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { email, password, name, role, dept, active, permissions } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await q(
      `INSERT INTO app_users (email, password, name, role, dept, active, permissions, frontend_access, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, TRUE, NOW(), $8)
       RETURNING id, email, name, role, dept, active, permissions, frontend_access, created_at, updated_at`,
      [email, hashedPassword, name || email, role || 'seller', dept || defaultDeptForRole(role), active !== false, JSON.stringify(permissions || defaultPermissionsForRole(role || 'seller')), req.user.email]
    );
    res.json(publicUser(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/password', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id } = req.params;
    const { newPassword, password } = req.body || {};
    const updatedUser = await updateUserPasswordPersistently({
      id,
      newPassword: newPassword || password,
      actorEmail: req.user.email
    });
    res.json({
      ok: true,
      message: 'Password saved to PostgreSQL successfully',
      user: updatedUser,
      passwordUpdatedAt: updatedUser.passwordUpdatedAt,
      passwordVersion: updatedUser.passwordVersion
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/api/users/password', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id, email, newPassword, password } = req.body || {};
    const updatedUser = await updateUserPasswordPersistently({
      id,
      email,
      newPassword: newPassword || password,
      actorEmail: req.user.email
    });
    res.json({
      ok: true,
      message: 'Password saved to PostgreSQL successfully',
      user: updatedUser,
      passwordUpdatedAt: updatedUser.passwordUpdatedAt,
      passwordVersion: updatedUser.passwordVersion
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.put('/api/users/:id/toggle', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const found = await q('SELECT id, active FROM app_users WHERE id = $1', [req.params.id]);
    const user = found.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const active = user.active === false;
    await q(
      `UPDATE app_users SET active = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3`,
      [active, req.user.email, req.params.id]
    );
    res.json({ ok: true, active });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const result = await q('DELETE FROM app_users WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, deletedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id } = req.params;
    const { name, email, role, dept, active, permissions } = req.body;
    const normalizedRole = role || 'seller';
    const result = await q(
      `UPDATE app_users
       SET name = COALESCE($1, name),
           email = COALESCE($2, email),
           role = COALESCE($3, role),
           dept = COALESCE($4, dept),
           active = COALESCE($5, active),
           permissions = COALESCE($6::jsonb, permissions),
           updated_at = NOW(),
           updated_by = $7
       WHERE id = $8
       RETURNING id, email, name, role, dept, active, permissions, frontend_access, created_at, updated_at`,
      [name || null, email || null, normalizedRole, dept || defaultDeptForRole(normalizedRole), typeof active === 'boolean' ? active : null, permissions ? JSON.stringify(permissions) : null, req.user.email, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'User not found' });
    const passwordToSave = req.body?.newPassword || req.body?.password;
    if (passwordToSave) {
      const updatedWithPassword = await updateUserPasswordPersistently({ id, newPassword: passwordToSave, actorEmail: req.user.email });
      return res.json(updatedWithPassword);
    }
    res.json(publicUser(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});


app.get('/api/admin/overview', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;

    const [usersResult, sectionsResult, lastStateUpdate] = await Promise.all([
      q('SELECT COUNT(*)::int AS count FROM app_users'),
      q('SELECT COUNT(*)::int AS count FROM app_state'),
      q('SELECT MAX(updated_at) AS last_backup FROM app_state')
    ]);

    res.json({
      userCount: usersResult.rows[0]?.count || 0,
      sectionCount: sectionsResult.rows[0]?.count || 0,
      lastBackup: lastStateUpdate.rows[0]?.last_backup || null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════
// ADMIN DATA SECTIONS - PostgreSQL relational bridge
// Every dashboard data section is backed by real PostgreSQL tables.
// app_state is kept only as a compatibility mirror for older screens.
// ═══════════════════════════════════════
const TABLE_BACKED_STATE_KEYS = new Set(Object.keys(DEFAULT_STATE));
const COUNTER_STATE_KEYS = new Set(['bq_inv_counter', 'bq_qt_counter']);

const TABLE_SECTION_META = {
  bq_products: { table: 'products', source: 'products_table' },
  bq_sales: { table: 'sales', source: 'sales_table' },
  bq_customers: { table: 'customers', source: 'customers_table' },
  bq_suppliers: { table: 'suppliers', source: 'suppliers_table' },
  bq_expenses: { table: 'expenses', source: 'expenses_table' },
  bq_purchases: { table: 'purchases', source: 'purchases_table' },
  bq_installments: { table: 'installments', source: 'installments_table' },
  bq_employees: { table: 'employees', source: 'employees_table' },
  bq_leaves: { table: 'employee_leaves', source: 'employee_leaves_table' },
  bq_pur_inst: { table: 'purchase_installments', source: 'purchase_installments_table' },
  bq_inv_counter: { table: 'app_counters', source: 'app_counters_table' },
  bq_qt_counter: { table: 'app_counters', source: 'app_counters_table' }
};

function sectionTypeOf(value) {
  return Array.isArray(value) ? 'array' : typeof value;
}

function sectionCountOf(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return value === undefined || value === null ? 0 : 1;
}

function badRequest(message) {
  const err = new Error(message);
  err.status = 400;
  return err;
}

async function getCounterValue(key) {
  const r = await q('SELECT value FROM app_counters WHERE key = $1', [key]);
  if (r.rows[0]) return rowCounter(r.rows[0], DEFAULT_STATE[key]);
  await q(
    `INSERT INTO app_counters (key, value, created_at, updated_at, updated_by)
     VALUES ($1, $2, NOW(), NOW(), 'system')
     ON CONFLICT (key) DO NOTHING`,
    [key, Number(DEFAULT_STATE[key] || 1)]
  );
  return Number(DEFAULT_STATE[key] || 1);
}

async function getAdminSectionValue(key) {
  if (key === 'bq_products') {
    const result = await q('SELECT * FROM products ORDER BY id');
    return result.rows.map(rowProduct);
  }
  if (key === 'bq_sales') {
    const result = await q('SELECT * FROM sales ORDER BY date DESC, id DESC');
    return result.rows.map(rowSale);
  }
  if (key === 'bq_customers') {
    const result = await q('SELECT * FROM customers ORDER BY id');
    return result.rows.map(rowCustomer);
  }
  if (key === 'bq_suppliers') {
    const result = await q('SELECT * FROM suppliers ORDER BY id');
    return result.rows.map(rowSupplier);
  }
  if (key === 'bq_expenses') {
    const result = await q('SELECT * FROM expenses ORDER BY date DESC, id DESC');
    return result.rows.map(rowExpense);
  }
  if (key === 'bq_purchases') {
    const result = await q('SELECT * FROM purchases ORDER BY date DESC, id DESC');
    return result.rows.map(rowPurchase);
  }
  if (key === 'bq_installments') {
    const result = await q('SELECT * FROM installments ORDER BY COALESCE(due_date, created_at::date) ASC, id DESC');
    return result.rows.map(rowInstallment);
  }
  if (key === 'bq_employees') {
    const result = await q('SELECT * FROM employees ORDER BY id');
    return result.rows.map(rowEmployee);
  }
  if (key === 'bq_leaves') {
    const result = await q('SELECT * FROM employee_leaves ORDER BY COALESCE(from_date, created_at::date) DESC, id DESC');
    return result.rows.map(rowLeave);
  }
  if (key === 'bq_pur_inst') {
    const result = await q('SELECT * FROM purchase_installments ORDER BY COALESCE(due_date, created_at::date) ASC, id DESC');
    return result.rows.map(rowPurchaseInstallment);
  }
  if (key === 'bq_settings') {
    const result = await q('SELECT value FROM app_state WHERE key = $1', [key]);
    return result.rows[0]?.value || DEFAULT_STATE[key] || {};
  }
  if (COUNTER_STATE_KEYS.has(key)) return getCounterValue(key);

  throw badRequest('Invalid state key');
}

async function getAdminSectionAudit(key) {
  if (key === 'bq_settings') {
    const r = await q('SELECT updated_at, updated_by, value FROM app_state WHERE key = $1', [key]);
    return { updatedAt: r.rows[0]?.updated_at || null, updatedBy: r.rows[0]?.updated_by || null, count: sectionCountOf(r.rows[0]?.value || DEFAULT_STATE[key] || {}), source: 'app_state_jsonb' };
  }
  const meta = TABLE_SECTION_META[key];
  if (!meta) return { updatedAt: null, updatedBy: null, count: 0, source: 'unknown' };

  if (COUNTER_STATE_KEYS.has(key)) {
    const r = await q('SELECT updated_at, updated_by, value FROM app_counters WHERE key = $1', [key]);
    return { updatedAt: r.rows[0]?.updated_at || null, updatedBy: r.rows[0]?.updated_by || null, count: 1, source: meta.source };
  }

  const table = meta.table;
  const timeColumn = table === 'sales' || table === 'purchases' || table === 'expenses' ? 'date' : 'created_at';
  const r = await q(`SELECT MAX(COALESCE(updated_at, ${timeColumn})) AS updated_at, COUNT(*)::int AS count FROM ${table}`);
  return { updatedAt: r.rows[0]?.updated_at || null, updatedBy: null, count: r.rows[0]?.count || 0, source: meta.source };
}

async function mirrorSectionState(key, value, userEmail) {
  await q(
    `INSERT INTO app_state (key, value, created_at, updated_at, updated_by)
     VALUES ($1, $2::jsonb, NOW(), NOW(), $3)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
    [key, JSON.stringify(value), userEmail]
  );
}

async function replaceTableBackedSection(key, value, userEmail) {
  if (!ALLOWED_STATE_KEYS.has(key)) throw badRequest('Invalid state key');

  if (COUNTER_STATE_KEYS.has(key)) {
    const n = Number(value);
    if (!Number.isFinite(n)) throw badRequest('Counter value must be a number');
    await q(
      `INSERT INTO app_counters (key, value, created_at, updated_at, updated_by)
       VALUES ($1, $2, NOW(), NOW(), $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
      [key, Math.trunc(n), userEmail]
    );
    const fresh = await getAdminSectionValue(key);
    await mirrorSectionState(key, fresh, userEmail);
    return fresh;
  }

  if (key === 'bq_settings') {
    const safe = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    await mirrorSectionState(key, safe, userEmail);
    return await getAdminSectionValue(key);
  }

  if (!Array.isArray(value)) throw badRequest('This section must be an array');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (key === 'bq_products') {
      await client.query('TRUNCATE products RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const code = String(row.code || legacyId(row, 'product'));
        const name = String(row.name || row.title || code);
        await insertWithOptionalId(
          client,
          'products',
          ['legacy_id', 'code', 'name', 'category', 'buy_price', 'sell_price', 'stock_qty', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'product'), code, name, row.category || 'أخرى', Number(row.buy_price || 0), Number(row.sell_price || 0), Math.max(0, Number(row.stock_qty || 0)), row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'products');
    } else if (key === 'bq_sales') {
      await client.query('TRUNCATE sales RESTART IDENTITY');
      let idx = 1;
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const items = Array.isArray(row.items) ? row.items : [];
        const total = Number(row.total || 0);
        const paid = Number(row.paid || 0);
        await insertWithOptionalId(
          client,
          'sales',
          ['legacy_id', 'invoice_no', 'customer_name', 'items', 'total', 'payment_type', 'paid', 'remaining', 'notes', 'date', 'created_by'],
          [legacyId(row, 'sale'), row.invoice_no || `INV-${String(idx++).padStart(5, '0')}`, row.customer_name || 'زبون عام', JSON.stringify(items), total, row.payment_type || 'cash', paid, Number(row.remaining ?? (total - paid)), row.notes || '', row.date || new Date(), row.seller_email || row.user_email || row.createdBy || row.created_by || userEmail],
          row
        );
      }
      await resetSerial(client, 'sales');
    } else if (key === 'bq_customers') {
      await client.query('TRUNCATE customers RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const name = String(row.name || row.customer_name || '').trim();
        if (!name) continue;
        await insertWithOptionalId(
          client,
          'customers',
          ['legacy_id', 'name', 'phone', 'email', 'address', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'customer'), name, row.phone || '', row.email || '', row.address || '', row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'customers');
    } else if (key === 'bq_suppliers') {
      await client.query('TRUNCATE suppliers RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const name = String(row.name || row.supplier_name || '').trim();
        if (!name) continue;
        await insertWithOptionalId(
          client,
          'suppliers',
          ['legacy_id', 'name', 'phone', 'email', 'address', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'supplier'), name, row.phone || '', row.email || '', row.address || '', row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'suppliers');
    } else if (key === 'bq_expenses') {
      await client.query('TRUNCATE expenses RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const title = String(row.description || row.statement || row.title || row.name || row.category || 'مصروف').trim();
        await insertWithOptionalId(
          client,
          'expenses',
          ['legacy_id', 'title', 'category', 'amount', 'date', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'expense'), title, row.category || 'عام', Number(row.amount || 0), row.date || new Date(), row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'expenses');
    } else if (key === 'bq_purchases') {
      await client.query('TRUNCATE purchases RESTART IDENTITY');
      let idx = 1;
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const items = Array.isArray(row.items) ? row.items : [];
        const total = Number(row.total || 0);
        const paid = Number(row.paid ?? row.paid_amt ?? 0);
        const paymentType = row.payment_type || row.pay_type || 'cash';
        await insertWithOptionalId(
          client,
          'purchases',
          ['legacy_id', 'invoice_no', 'supplier_name', 'items', 'total', 'payment_type', 'paid', 'remaining', 'notes', 'date', 'created_by'],
          [legacyId(row, 'purchase'), row.invoice_no || `PUR-${String(idx++).padStart(5, '0')}`, row.supplier_name || 'مورد عام', JSON.stringify(items), total, paymentType, paid, Number(row.remaining ?? (total - paid)), row.notes || '', row.date || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'purchases');
    } else if (key === 'bq_installments') {
      await client.query('TRUNCATE installments RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const amount = Number(row.amount || row.total || 0);
        const paid = Number(row.paid || 0);
        await insertWithOptionalId(
          client,
          'installments',
          ['legacy_id', 'customer_name', 'amount', 'paid', 'remaining', 'due_date', 'status', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'installment'), row.customer_name || row.customer || '', amount, paid, Number(row.remaining ?? (amount - paid)), row.due_date || null, row.status || 'pending', row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'installments');
    } else if (key === 'bq_employees') {
      await client.query('TRUNCATE employees RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const name = String(row.name || '').trim();
        const role = String(row.role || row.job || '').trim();
        if (!name || !role) continue;
        const salary = Number(row.salary || 0);
        const housing = Number(row.housing || 0);
        const transport = Number(row.transport || 0);
        const other = Number(row.other ?? row.other_amount ?? 0);
        const total = Number(row.total || (salary + housing + transport + other));
        await insertWithOptionalId(
          client,
          'employees',
          ['legacy_id', 'name', 'nationality', 'role', 'salary', 'housing', 'transport', 'other_amount', 'total', 'created_at', 'created_by'],
          [legacyId(row, 'employee'), name, row.nationality || '', role, salary, housing, transport, other, total, row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'employees');
    } else if (key === 'bq_leaves') {
      await client.query('TRUNCATE employee_leaves RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        await insertWithOptionalId(
          client,
          'employee_leaves',
          ['legacy_id', 'employee_name', 'employee_id', 'from_date', 'to_date', 'reason', 'status', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'leave'), row.employee_name || row.emp_name || row.employee || '', numericId({id: row.employee_id || row.emp_id}) || null, row.from || row.from_date || null, row.to || row.to_date || null, row.reason || '', row.status || 'pending', row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'employee_leaves');
    } else if (key === 'bq_pur_inst') {
      await client.query('TRUNCATE purchase_installments RESTART IDENTITY');
      for (const row of value) {
        if (!row || typeof row !== 'object') continue;
        const amount = Number(row.amount || row.total || 0);
        const paid = Number(row.paid || 0);
        await insertWithOptionalId(
          client,
          'purchase_installments',
          ['legacy_id', 'supplier_name', 'amount', 'paid', 'remaining', 'due_date', 'status', 'notes', 'created_at', 'created_by'],
          [legacyId(row, 'purchase_installment'), row.supplier_name || row.supplier || '', amount, paid, Number(row.remaining ?? (amount - paid)), row.due_date || null, row.status || 'pending', row.notes || '', row.createdAt || new Date(), userEmail],
          row
        );
      }
      await resetSerial(client, 'purchase_installments');
    }

    await client.query('COMMIT');
    const fresh = await getAdminSectionValue(key);
    await mirrorSectionState(key, fresh, userEmail);
    return fresh;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function resetAdminSection(key, userEmail) {
  if (!ALLOWED_STATE_KEYS.has(key)) throw badRequest('Invalid state key');

  if (COUNTER_STATE_KEYS.has(key)) {
    const fresh = Number(DEFAULT_STATE[key] || 1);
    await replaceTableBackedSection(key, fresh, userEmail);
    return fresh;
  }

  if (key === 'bq_settings') {
    await mirrorSectionState(key, DEFAULT_STATE[key] || {}, userEmail);
    return await getAdminSectionValue(key);
  }

  const table = TABLE_SECTION_META[key]?.table;
  if (!table) throw badRequest('Invalid state key');
  await q(`TRUNCATE ${table} RESTART IDENTITY`);

  if (key === 'bq_products') {
    await seedDefaultProductsTable();
  }

  const fresh = await getAdminSectionValue(key);
  await mirrorSectionState(key, fresh, userEmail);
  return fresh;
}

app.get('/api/admin/sections', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const sections = [];
    for (const key of Object.keys(DEFAULT_STATE)) {
      const [value, audit] = await Promise.all([getAdminSectionValue(key), getAdminSectionAudit(key)]);
      sections.push({
        key,
        label: STATE_LABELS[key] || key,
        type: sectionTypeOf(value),
        count: audit.count ?? sectionCountOf(value),
        updatedAt: audit.updatedAt || null,
        updatedBy: audit.updatedBy || null,
        source: audit.source || 'database_table',
        tableBacked: true,
        databaseBacked: true
      });
    }
    res.json(sections);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/section/:key', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { key } = req.params;
    if (!ALLOWED_STATE_KEYS.has(key)) return res.status(400).json({ error: 'Invalid state key' });
    const [value, audit] = await Promise.all([getAdminSectionValue(key), getAdminSectionAudit(key)]);
    res.json({
      key,
      label: STATE_LABELS[key] || key,
      value,
      type: sectionTypeOf(value),
      count: audit.count ?? sectionCountOf(value),
      updatedAt: audit.updatedAt || null,
      updatedBy: audit.updatedBy || null,
      source: audit.source || 'database_table',
      tableBacked: true,
      databaseBacked: true
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.put('/api/admin/section/:key', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { key } = req.params;
    if (!ALLOWED_STATE_KEYS.has(key)) return res.status(400).json({ error: 'Invalid state key' });
    const { value } = req.body;
    const fresh = await replaceTableBackedSection(key, value, req.user.email);
    res.json({ ok: true, key, label: STATE_LABELS[key] || key, count: sectionCountOf(fresh), tableBacked: true, databaseBacked: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.delete('/api/admin/section/:key', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { key } = req.params;
    if (!ALLOWED_STATE_KEYS.has(key)) return res.status(400).json({ error: 'Invalid state key' });
    const fresh = await resetAdminSection(key, req.user.email);
    res.json({ ok: true, key, reset: true, count: sectionCountOf(fresh), tableBacked: true, databaseBacked: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/api/admin/backup/restore', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const state = req.body?.state || req.body;
    if (!state || typeof state !== 'object') return res.status(400).json({ error: 'Invalid backup payload' });
    let restored = 0;
    for (const [key, value] of Object.entries(state)) {
      if (!ALLOWED_STATE_KEYS.has(key)) continue;
      await replaceTableBackedSection(key, value, req.user.email);
      restored += 1;
    }
    res.json({ ok: true, restored });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// Compatibility route if an older admin HTML calls /api/backup/restore
app.post('/api/backup/restore', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const state = req.body?.state || req.body;
    if (!state || typeof state !== 'object') return res.status(400).json({ error: 'Invalid backup payload' });
    let restored = 0;
    for (const [key, value] of Object.entries(state)) {
      if (!ALLOWED_STATE_KEYS.has(key)) continue;
      await replaceTableBackedSection(key, value, req.user.email);
      restored += 1;
    }
    res.json({ ok: true, restored });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});


app.post('/api/admin/sync-database', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    await migrateExistingAppStateToRelationalTables();
    await syncAllSectionsToState(req.user.email);
    res.json({ ok: true, message: 'Database synchronized from app_state and compatibility mirror updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/meta', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    res.json({ modules: FRONTEND_MODULES, sellerModules: SELLER_MODULES, stateLabels: STATE_LABELS });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/activity/log', optionalAuthenticate, async (req, res) => {
  try {
    const rawAction = String(req.body?.action || 'حدث من الواجهة').trim();
    if (!rawAction) return res.status(400).json({ error: 'Action is required' });
    const action = frontendEventDescription({ ...req.body, action: rawAction });
    if (!action) return res.json({ ok: true, skipped: true });
    await logActivity({ action, user: req.user?.email || req.body?.user || req.headers['x-user-email'] || 'guest', source: inferActivitySource(req), page: req.body?.page || req.headers['x-bq-page'] || null, entity: req.body?.entity || 'frontend_event', entityId: req.body?.entityId || req.body?.entity_id || null, method: 'EVENT', path: req.body?.path || req.originalUrl || req.path, statusCode: 200, level: req.body?.level || 'info', details: jsonSafe({ ...(req.body?.details || {}), rawAction }), ip: clientIp(req), userAgent: req.headers['user-agent'] || '' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/monitor/stats', authenticate, async (req, res) => {
  try {
    const state = await getStateMap();
    const usersResult = await q('SELECT active FROM app_users');
    const sizeResult = await q('SELECT pg_database_size(current_database())::bigint AS size');
    const activityResult = await q('SELECT COUNT(*)::int AS count FROM app_activity_logs');
    const memory = process.memoryUsage();

    res.json({
      salesCount: Array.isArray(state.bq_sales) ? state.bq_sales.length : 0,
      productsCount: Array.isArray(state.bq_products) ? state.bq_products.length : 0,
      customersCount: Array.isArray(state.bq_customers) ? state.bq_customers.length : 0,
      activeUsers: usersResult.rows.filter(u => u.active !== false).length,
      uptime: process.uptime(),
      memoryUsed: memory.heapUsed,
      memoryTotal: memory.heapTotal,
      dbSizeBytes: Number(sizeResult.rows[0]?.size || 0),
      requestCount,
      activityCount: activityResult.rows[0]?.count || 0,
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
      database: 'PostgreSQL'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/monitor/log-users', authenticate, async (req, res) => {
  try {
    const result = await q(
      `SELECT COALESCE(user_email, 'system') AS email, COUNT(*)::int AS count
       FROM app_activity_logs
       GROUP BY COALESCE(user_email, 'system')
       ORDER BY count DESC, email ASC
       LIMIT 200`
    );
    res.json(result.rows.map(row => ({ email: row.email, count: row.count })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/monitor/logs', authenticate, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 80), 1), 300);
    const source = req.query.source ? String(req.query.source) : null;
    const entity = req.query.entity ? String(req.query.entity) : null;
    const user = req.query.user ? String(req.query.user) : null;
    const level = req.query.level ? String(req.query.level) : null;
    const qText = req.query.q ? String(req.query.q).trim() : null;
    const dateFrom = req.query.date_from ? String(req.query.date_from) : null;
    const dateTo = req.query.date_to ? String(req.query.date_to) : null;
    const params = [];
    const where = [];
    if (source) { params.push(source); where.push(`source = $${params.length}`); }
    if (entity) { params.push(entity); where.push(`entity = $${params.length}`); }
    if (user) { params.push(user); where.push(`COALESCE(user_email, 'system') = $${params.length}`); }
    if (level) { params.push(level); where.push(`level = $${params.length}`); }
    if (dateFrom) { params.push(dateFrom); where.push(`created_at >= $${params.length}::timestamptz`); }
    if (dateTo) { params.push(dateTo); where.push(`created_at <= $${params.length}::timestamptz`); }
    if (qText) { params.push(`%${qText}%`); where.push(`(action ILIKE $${params.length} OR path ILIKE $${params.length} OR COALESCE(user_email, '') ILIKE $${params.length})`); }
    params.push(limit);
    const result = await q(
      `SELECT id, action, COALESCE(user_email, 'system') AS user, source, page, entity,
              entity_id AS "entityId", method, path, status_code AS "statusCode",
              level, details, created_at AS timestamp
       FROM app_activity_logs
       ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
       ORDER BY created_at DESC, id DESC
       LIMIT $${params.length}`,
      params
    );
    res.json(result.rows.map(row => ({ id: String(row.id), action: row.action, user: row.user || 'system', source: row.source || 'api', page: row.page, entity: row.entity, entityId: row.entityId, method: row.method, path: row.path, statusCode: row.statusCode, level: row.level, details: row.details || {}, timestamp: row.timestamp })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/backup', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const [users, products, sales, customers, suppliers, expenses, purchases, installments, employees, leaves, purchaseInstallments] = await Promise.all([
      q('SELECT id, email, name, role, dept, active, permissions, created_at, updated_at FROM app_users ORDER BY id'),
      q('SELECT * FROM products ORDER BY id'),
      q('SELECT * FROM sales ORDER BY id'),
      q('SELECT * FROM customers ORDER BY id'),
      q('SELECT * FROM suppliers ORDER BY id'),
      q('SELECT * FROM expenses ORDER BY id'),
      q('SELECT * FROM purchases ORDER BY id'),
      q('SELECT * FROM installments ORDER BY id'),
      q('SELECT * FROM employees ORDER BY id'),
      q('SELECT * FROM employee_leaves ORDER BY id'),
      q('SELECT * FROM purchase_installments ORDER BY id')
    ]);

    res.json({
      generatedAt: new Date(),
      database: 'PostgreSQL',
      users: users.rows.map(publicUser),
      state: await getStateMap(),
      products: products.rows.map(rowProduct),
      sales: sales.rows.map(rowSale),
      customers: customers.rows.map(rowCustomer),
      suppliers: suppliers.rows.map(rowSupplier),
      expenses: expenses.rows.map(rowExpense),
      purchases: purchases.rows.map(rowPurchase),
      installments: installments.rows.map(rowInstallment),
      employees: employees.rows.map(rowEmployee),
      leaves: leaves.rows.map(rowLeave),
      purchaseInstallments: purchaseInstallments.rows.map(rowPurchaseInstallment)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// PRODUCTS ENDPOINTS - Compatibility with older screens
// ═══════════════════════════════════════
app.get('/api/products', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM products ORDER BY id');
    res.json(result.rows.map(rowProduct));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/products', authenticate, async (req, res) => {
  try {
    const { code, name, category, buy_price, sell_price, stock_qty, notes } = req.body;
    if (!code || !name) return res.status(400).json({ error: 'Code and name required' });
    const stockQty = Number(stock_qty || 0);
    if (!Number.isFinite(stockQty) || stockQty < 0) {
      return res.status(400).json({ error: 'كمية المنتج يجب أن تكون أكبر من أو تساوي 0' });
    }

    const result = await q(
      `INSERT INTO products (code, name, category, buy_price, sell_price, stock_qty, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
       RETURNING *`,
      [code, name, category || 'أخرى', Number(buy_price || 0), Number(sell_price || 0), stockQty, notes || '', req.user.email]
    );
    res.json(rowProduct(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') {
      if (String(err.constraint || '').includes('products_pkey')) {
        await resetSerial(pool, 'products');
        return res.status(409).json({ error: 'تم ضبط تسلسل المنتجات. جرّب إضافة المنتج مرة أخرى.' });
      }
      return res.status(409).json({ error: 'كود المنتج موجود بالفعل' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/products/:id', authenticate, async (req, res) => {
  try {
    const { code, name, category, buy_price, sell_price, stock_qty, notes } = req.body;
    const stockQty = Number(stock_qty || 0);
    if (!Number.isFinite(stockQty) || stockQty < 0) {
      return res.status(400).json({ error: 'كمية المنتج يجب أن تكون أكبر من أو تساوي 0' });
    }
    const result = await q(
      `UPDATE products
       SET code = $1, name = $2, category = $3, buy_price = $4, sell_price = $5,
           stock_qty = $6, notes = $7, updated_at = NOW(), updated_by = $8
       WHERE id = $9`,
      [code, name, category, Number(buy_price || 0), Number(sell_price || 0), stockQty, notes || '', req.user.email, req.params.id]
    );
    res.json({ acknowledged: true, modifiedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM products WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// SALES ENDPOINTS
// ═══════════════════════════════════════
app.get('/api/sales', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM sales ORDER BY date DESC, id DESC');
    res.json(result.rows.map(rowSale));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


async function getCurrentDbUser(req) {
  const result = await q('SELECT id, email, name, role FROM app_users WHERE id = $1 OR email = $2 LIMIT 1', [req.user?.id || null, req.user?.email || null]);
  return result.rows[0] || { id: req.user?.id, email: req.user?.email, name: req.user?.email, role: req.user?.role };
}

function normalizeOwnerValue(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[\u064B-\u065F\u0670]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function compactOwnerValue(value) {
  return normalizeOwnerValue(value).replace(/[\s_\-.]+/g, '');
}

function identityValuesForUser(user) {
  const values = [user?.email, user?.name, user?.id, user?._id, user?.db_id]
    .map(normalizeOwnerValue)
    .filter(Boolean);
  const email = normalizeOwnerValue(user?.email);
  if (email && email.includes('@')) values.push(email.split('@')[0]);
  return [...new Set([...values, ...values.map(compactOwnerValue).filter(Boolean)])];
}

function ownerValuesForRecord(record) {
  if (!record || typeof record !== 'object') return [];
  const keys = [
    'user_name','seller_name','seller_email','user_email','createdBy','created_by','created_by_email',
    'updatedBy','updated_by','owner','owner_email','addedBy','added_by','employee_email'
  ];
  const values = [];
  keys.forEach(k => { if (record?.[k] !== undefined && record?.[k] !== null) values.push(record[k]); });
  if (record.data && typeof record.data === 'object') {
    keys.forEach(k => { if (record.data?.[k] !== undefined && record.data?.[k] !== null) values.push(record.data[k]); });
  }

  function scan(obj, depth = 0) {
    if (!obj || typeof obj !== 'object' || depth > 3) return;
    for (const [k, v] of Object.entries(obj)) {
      const key = String(k).toLowerCase();
      if (v && typeof v === 'object') { scan(v, depth + 1); continue; }
      if (/(seller|user|created|updated|owner|by|email|مندوب|بائع)/i.test(key)) values.push(v);
    }
  }
  scan(record);
  return [...new Set(values.map(normalizeOwnerValue).filter(Boolean))];
}

function recordMatchesOwner(record, user) {
  const me = identityValuesForUser(user);
  const owners = ownerValuesForRecord(record);

  if (!owners.length) return false;

  return owners.some(owner => {
    const compactOwner = compactOwnerValue(owner);
    return me.some(id => {
      const compactId = compactOwnerValue(id);
      return owner === id || compactOwner === compactId ||
        (compactId.length >= 4 && compactOwner.includes(compactId)) ||
        (compactOwner.length >= 4 && compactId.includes(compactOwner));
    });
  });
}


app.get('/api/sales/mine', authenticate, async (req, res) => {
  try {
    const user = await getCurrentDbUser(req);
    const result = await q('SELECT * FROM sales ORDER BY date DESC, id DESC');
    const allRows = result.rows.map(rowSale);

    if (user.role !== 'seller') {
      return res.json({ sales: allRows, user: publicUser(user), total: allRows.length });
    }

    let rows = allRows.filter(row => recordMatchesOwner(row, user));

    // fallback إضافي للسجلات القديمة: مطابقة على created_by في الجدول الخام لو rowSale فقد حقل من JSON.
    if (!rows.length) {
      const ids = identityValuesForUser(user);
      const rawMatches = result.rows.filter(r => {
        const raw = rowRaw(r);
        const owners = ownerValuesForRecord({ ...raw, ...r, data: raw });
        return owners.some(owner => {
          const compactOwner = compactOwnerValue(owner);
          return ids.some(id => {
            const compactId = compactOwnerValue(id);
            return owner === id || compactOwner === compactId ||
              (compactId.length >= 4 && compactOwner.includes(compactId)) ||
              (compactOwner.length >= 4 && compactId.includes(compactOwner));
          });
        });
      });
      rows = rawMatches.map(rowSale);
    }

    // fallback نهائي: لو المستخدم هو أول بائع نشط، اعرض الفواتير القديمة التي لا تحمل مالكًا واضحًا.
    // هذا يحل فواتير localStorage القديمة التي دخلت قاعدة البيانات قبل تسجيل seller_email.
    if (!rows.length && user.role === 'seller') {
      const sellers = await getActiveSellersForRepair();
      const firstSeller = sellers[0];
      if (firstSeller && normalizeOwnerValue(firstSeller.email) === normalizeOwnerValue(user.email)) {
        rows = allRows.filter(row => {
          const owners = ownerValuesForRecord(row);
          const ownerText = owners.join(' ');
          return !owners.length || /state-migration|system|admin@|admin/i.test(ownerText);
        });
      }
    }

    res.json({ sales: rows, user: publicUser(user), total: rows.length, scanned: allRows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post('/api/sales/repair-legacy-owners', authenticate, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    await repairLegacySalesOwners();
    const result = await q('SELECT * FROM sales ORDER BY date DESC, id DESC');
    res.json({ ok: true, sales: result.rows.map(rowSale) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/installments/mine', authenticate, async (req, res) => {
  try {
    const user = await getCurrentDbUser(req);
    const salesResult = await q('SELECT * FROM sales ORDER BY date DESC, id DESC');
    const sellerSales = salesResult.rows.map(rowSale).filter(row => user.role !== 'seller' || recordMatchesOwner(row, user));
    const saleIds = new Set(sellerSales.flatMap(s => [String(s.id || ''), String(s._id || ''), String(s.db_id || ''), String(s.legacy_id || '')]).filter(Boolean));
    const invoiceNos = new Set(sellerSales.map(s => String(s.invoice_no || '')).filter(Boolean));

    const instResult = await q('SELECT * FROM installments ORDER BY COALESCE(due_date, created_at::date) ASC, id DESC');
    const rows = instResult.rows.map(rowInstallment).filter(row => {
      if (user.role !== 'seller') return true;
      const saleId = String(row.sale_id || '');
      const invNo = String(row.invoice_no || '');
      return (saleId && saleIds.has(saleId)) || (invNo && invoiceNos.has(invNo)) || recordMatchesOwner(row, user);
    });
    res.json({ installments: rows, user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sales', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { invoice_no, customer_name, items, total, payment_type, paid, notes } = req.body;
    if (!invoice_no || !items) return res.status(400).json({ error: 'Invoice number and items required' });

    const totalNum = Number(total || 0);
    const paidNum = Number(paid || 0);
    await client.query('BEGIN');

    for (const item of items || []) {
      if (item.pid && Number.isFinite(Number(item.pid))) {
        const qty = Number(item.qty || 0);
        const product = await client.query('SELECT id, name, stock_qty FROM products WHERE id = $1 FOR UPDATE', [item.pid]);
        if (!product.rowCount) continue;
        const available = Number(product.rows[0].stock_qty || 0);
        if (qty < 0) {
          const err = new Error('كمية الصنف يجب أن تكون أكبر من أو تساوي 0');
          err.status = 400;
          throw err;
        }
        if (qty > available) {
          const err = new Error(`لا توجد كمية كافية من المنتج: ${product.rows[0].name} — المتاح ${available}`);
          err.status = 400;
          throw err;
        }
      }
    }

    const result = await client.query(
      `INSERT INTO sales (invoice_no, customer_name, items, total, payment_type, paid, remaining, notes, date, created_by)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, NOW(), $9)
       RETURNING *`,
      [invoice_no, customer_name || 'زبون عام', JSON.stringify(items || []), totalNum, payment_type || 'cash', paidNum, totalNum - paidNum, notes || '', req.user.email]
    );

    for (const item of items || []) {
      if (item.pid && Number.isFinite(Number(item.pid))) {
        await client.query('UPDATE products SET stock_qty = GREATEST(0, stock_qty - $1) WHERE id = $2', [Number(item.qty || 0), item.pid]);
      }
    }

    await client.query('COMMIT');
    res.json(rowSale(result.rows[0]));
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'Invoice number already exists' });
    res.status(err.status || 500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.put('/api/sales/:id', authenticate, async (req, res) => {
  try {
    const { customer_name, payment_type, paid, notes } = req.body;
    const sale = await q('SELECT total FROM sales WHERE id = $1', [req.params.id]);
    if (!sale.rowCount) return res.status(404).json({ error: 'Sale not found' });
    const paidNum = Number(paid || 0);
    const totalNum = Number(sale.rows[0].total || 0);
    const result = await q(
      `UPDATE sales
       SET customer_name = $1, payment_type = $2, paid = $3, remaining = $4, notes = $5, updated_at = NOW()
       WHERE id = $6`,
      [customer_name, payment_type, paidNum, totalNum - paidNum, notes || '', req.params.id]
    );
    res.json({ acknowledged: true, modifiedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/sales/:id', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const sale = await client.query('SELECT * FROM sales WHERE id = $1', [req.params.id]);
    if (!sale.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Sale not found' });
    }
    for (const item of sale.rows[0].items || []) {
      if (item.pid && Number.isFinite(Number(item.pid))) {
        await client.query('UPDATE products SET stock_qty = stock_qty + $1 WHERE id = $2', [Number(item.qty || 0), item.pid]);
      }
    }
    const result = await client.query('DELETE FROM sales WHERE id = $1', [req.params.id]);
    await client.query('COMMIT');
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ═══════════════════════════════════════
// PURCHASES ENDPOINTS
// ═══════════════════════════════════════
app.get('/api/purchases', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM purchases ORDER BY date DESC, id DESC');
    res.json(result.rows.map(rowPurchase));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/purchases', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { invoice_no, supplier_name, items, total, payment_type, paid, notes } = req.body;
    if (!invoice_no || !items) return res.status(400).json({ error: 'Invoice number and items required' });
    const totalNum = Number(total || 0);
    const paidNum = Number(paid || 0);

    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO purchases (invoice_no, supplier_name, items, total, payment_type, paid, remaining, notes, date, created_by)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, NOW(), $9)
       RETURNING *`,
      [invoice_no, supplier_name || 'مورد عام', JSON.stringify(items || []), totalNum, payment_type || 'cash', paidNum, totalNum - paidNum, notes || '', req.user.email]
    );

    for (const item of items || []) {
      if (item.pid && Number.isFinite(Number(item.pid))) {
        await client.query('UPDATE products SET stock_qty = stock_qty + $1 WHERE id = $2', [Number(item.qty || 0), item.pid]);
      }
    }

    await client.query('COMMIT');
    res.json(rowPurchase(result.rows[0]));
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'Invoice number already exists' });
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.put('/api/purchases/:id', authenticate, async (req, res) => {
  try {
    const { supplier_name, payment_type, paid, notes } = req.body;
    const purchase = await q('SELECT total FROM purchases WHERE id = $1', [req.params.id]);
    if (!purchase.rowCount) return res.status(404).json({ error: 'Purchase not found' });
    const paidNum = Number(paid || 0);
    const totalNum = Number(purchase.rows[0].total || 0);
    const result = await q(
      `UPDATE purchases
       SET supplier_name = $1, payment_type = $2, paid = $3, remaining = $4, notes = $5, updated_at = NOW()
       WHERE id = $6`,
      [supplier_name, payment_type, paidNum, totalNum - paidNum, notes || '', req.params.id]
    );
    res.json({ acknowledged: true, modifiedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/purchases/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM purchases WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// EMPLOYEES ENDPOINTS
// ═══════════════════════════════════════
app.get('/api/employees', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM employees ORDER BY id');
    res.json(result.rows.map(rowEmployee));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/employees', authenticate, async (req, res) => {
  try {
    const { name, nationality, role, salary, housing, transport, other } = req.body;
    if (!name || !role) return res.status(400).json({ error: 'Name and role required' });
    const salaryNum = Number(salary || 0);
    const housingNum = Number(housing || 0);
    const transportNum = Number(transport || 0);
    const otherNum = Number(other || 0);
    const total = salaryNum + housingNum + transportNum + otherNum;

    const result = await q(
      `INSERT INTO employees (name, nationality, role, salary, housing, transport, other_amount, total, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
       RETURNING *`,
      [name, nationality || '', role, salaryNum, housingNum, transportNum, otherNum, total, req.user.email]
    );
    res.json(rowEmployee(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/employees/:id', authenticate, async (req, res) => {
  try {
    const { name, nationality, role, salary, housing, transport, other } = req.body;
    const salaryNum = Number(salary || 0);
    const housingNum = Number(housing || 0);
    const transportNum = Number(transport || 0);
    const otherNum = Number(other || 0);
    const total = salaryNum + housingNum + transportNum + otherNum;
    const result = await q(
      `UPDATE employees
       SET name = $1, nationality = $2, role = $3, salary = $4, housing = $5, transport = $6,
           other_amount = $7, total = $8, updated_at = NOW()
       WHERE id = $9`,
      [name, nationality || '', role, salaryNum, housingNum, transportNum, otherNum, total, req.params.id]
    );
    res.json({ acknowledged: true, modifiedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/employees/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM employees WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════
// CUSTOMERS / SUPPLIERS / EXPENSES / INSTALLMENTS / LEAVES ENDPOINTS
// These endpoints are used by the main dashboard and the admin data screen.
// ═══════════════════════════════════════
app.get('/api/customers', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM customers ORDER BY id');
    res.json(result.rows.map(rowCustomer));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/customers', authenticate, async (req, res) => {
  try {
    const { name, phone, email, address, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Customer name required' });
    const result = await q(
      `INSERT INTO customers (legacy_id, name, phone, email, address, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7) RETURNING *`,
      [req.body.legacy_id || req.body.id || null, name, phone || '', email || '', address || '', notes || '', req.user.email]
    );
    res.json(rowCustomer(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/customers/:id', authenticate, async (req, res) => {
  try {
    const { name, phone, email, address, notes } = req.body;
    const result = await q(
      `UPDATE customers SET name = $1, phone = $2, email = $3, address = $4, notes = $5, updated_at = NOW(), updated_by = $6 WHERE id = $7 RETURNING *`,
      [name, phone || '', email || '', address || '', notes || '', req.user.email, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Customer not found' });
    res.json(rowCustomer(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/customers/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM customers WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/suppliers', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM suppliers ORDER BY id');
    res.json(result.rows.map(rowSupplier));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/suppliers', authenticate, async (req, res) => {
  try {
    const { name, phone, email, address, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Supplier name required' });
    const result = await q(
      `INSERT INTO suppliers (legacy_id, name, phone, email, address, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7) RETURNING *`,
      [req.body.legacy_id || req.body.id || null, name, phone || '', email || '', address || '', notes || '', req.user.email]
    );
    res.json(rowSupplier(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/suppliers/:id', authenticate, async (req, res) => {
  try {
    const { name, phone, email, address, notes } = req.body;
    const result = await q(
      `UPDATE suppliers SET name = $1, phone = $2, email = $3, address = $4, notes = $5, updated_at = NOW(), updated_by = $6 WHERE id = $7 RETURNING *`,
      [name, phone || '', email || '', address || '', notes || '', req.user.email, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Supplier not found' });
    res.json(rowSupplier(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/suppliers/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM suppliers WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/expenses', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM expenses ORDER BY date DESC, id DESC');
    res.json(result.rows.map(rowExpense));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/expenses', authenticate, async (req, res) => {
  try {
    const { title, category, amount, date, notes } = req.body;
    if (!title) return res.status(400).json({ error: 'Expense title required' });
    const result = await q(
      `INSERT INTO expenses (legacy_id, title, category, amount, date, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, NOW()), $6, NOW(), $7) RETURNING *`,
      [req.body.legacy_id || req.body.id || null, title, category || 'عام', Number(amount || 0), date || null, notes || '', req.user.email]
    );
    res.json(rowExpense(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/expenses/:id', authenticate, async (req, res) => {
  try {
    const { title, category, amount, date, notes } = req.body;
    const result = await q(
      `UPDATE expenses SET title = $1, category = $2, amount = $3, date = COALESCE($4::timestamptz, date), notes = $5, updated_at = NOW(), updated_by = $6 WHERE id = $7 RETURNING *`,
      [title, category || 'عام', Number(amount || 0), date || null, notes || '', req.user.email, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Expense not found' });
    res.json(rowExpense(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/expenses/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM expenses WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/installments', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM installments ORDER BY COALESCE(due_date, created_at::date) ASC, id DESC');
    res.json(result.rows.map(rowInstallment));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/installments', authenticate, async (req, res) => {
  try {
    const { customer_name, amount, paid, remaining, due_date, status, notes } = req.body;
    const amountNum = Number(amount || 0);
    const paidNum = Number(paid || 0);

    const result = await q(
      `INSERT INTO installments (
        legacy_id, customer_name, amount, paid, remaining,
        due_date, status, notes, data, created_at, created_by
      )
      VALUES ($1, $2, $3, $4, $5, $6::date, $7, $8, $9::jsonb, NOW(), $10)
      RETURNING *`,
      [
        req.body.legacy_id || req.body.id || null,
        customer_name || '',
        amountNum,
        paidNum,
        Number(remaining ?? (amountNum - paidNum)),
        due_date || null,
        status || 'pending',
        notes || '',
        JSON.stringify(req.body),
        req.user.email
      ]
    );

    res.json(rowInstallment(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.put('/api/installments/:id', authenticate, async (req, res) => {
  try {
    const { customer_name, amount, paid, remaining, due_date, status, notes } = req.body;
    const amountNum = Number(amount || 0);
    const paidNum = Number(paid || 0);

    const result = await q(
      `UPDATE installments SET
        customer_name = $1,
        amount = $2,
        paid = $3,
        remaining = $4,
        due_date = $5::date,
        status = $6,
        notes = $7,
        data = COALESCE(data, '{}'::jsonb) || $8::jsonb,
        updated_at = NOW(),
        updated_by = $9
      WHERE id = $10
      RETURNING *`,
      [
        customer_name || '',
        amountNum,
        paidNum,
        Number(remaining ?? (amountNum - paidNum)),
        due_date || null,
        status || 'pending',
        notes || '',
        JSON.stringify(req.body),
        req.user.email,
        req.params.id
      ]
    );

    if (!result.rowCount) return res.status(404).json({ error: 'Installment not found' });
    res.json(rowInstallment(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/installments/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM installments WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/leaves', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM employee_leaves ORDER BY COALESCE(from_date, created_at::date) DESC, id DESC');
    res.json(result.rows.map(rowLeave));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/leaves', authenticate, async (req, res) => {
  try {
    const { employee_name, employee_id, reason, status, notes } = req.body;
    const fromDate = req.body.from || req.body.from_date || null;
    const toDate = req.body.to || req.body.to_date || null;
    const result = await q(
      `INSERT INTO employee_leaves (legacy_id, employee_name, employee_id, from_date, to_date, reason, status, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4::date, $5::date, $6, $7, $8, NOW(), $9) RETURNING *`,
      [req.body.legacy_id || req.body.id || null, employee_name || '', numericId({id: employee_id}) || null, fromDate, toDate, reason || '', status || 'pending', notes || '', req.user.email]
    );
    res.json(rowLeave(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/leaves/:id', authenticate, async (req, res) => {
  try {
    const { employee_name, employee_id, reason, status, notes } = req.body;
    const fromDate = req.body.from || req.body.from_date || null;
    const toDate = req.body.to || req.body.to_date || null;
    const result = await q(
      `UPDATE employee_leaves SET employee_name = $1, employee_id = $2, from_date = $3::date, to_date = $4::date, reason = $5, status = $6, notes = $7, updated_at = NOW(), updated_by = $8 WHERE id = $9 RETURNING *`,
      [employee_name || '', numericId({id: employee_id}) || null, fromDate, toDate, reason || '', status || 'pending', notes || '', req.user.email, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Leave not found' });
    res.json(rowLeave(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/leaves/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM employee_leaves WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/purchase-installments', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM purchase_installments ORDER BY COALESCE(due_date, created_at::date) ASC, id DESC');
    res.json(result.rows.map(rowPurchaseInstallment));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/purchase-installments', authenticate, async (req, res) => {
  try {
    const { supplier_name, amount, paid, remaining, due_date, status, notes } = req.body;
    const amountNum = Number(amount || 0);
    const paidNum = Number(paid || 0);
    const result = await q(
      `INSERT INTO purchase_installments (legacy_id, supplier_name, amount, paid, remaining, due_date, status, notes, created_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6::date, $7, $8, NOW(), $9) RETURNING *`,
      [req.body.legacy_id || req.body.id || null, supplier_name || '', amountNum, paidNum, Number(remaining ?? (amountNum - paidNum)), due_date || null, status || 'pending', notes || '', req.user.email]
    );
    res.json(rowPurchaseInstallment(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/purchase-installments/:id', authenticate, async (req, res) => {
  try {
    const { supplier_name, amount, paid, remaining, due_date, status, notes } = req.body;
    const amountNum = Number(amount || 0);
    const paidNum = Number(paid || 0);
    const result = await q(
      `UPDATE purchase_installments SET supplier_name = $1, amount = $2, paid = $3, remaining = $4, due_date = $5::date, status = $6, notes = $7, updated_at = NOW(), updated_by = $8 WHERE id = $9 RETURNING *`,
      [supplier_name || '', amountNum, paidNum, Number(remaining ?? (amountNum - paidNum)), due_date || null, status || 'pending', notes || '', req.user.email, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Purchase installment not found' });
    res.json(rowPurchaseInstallment(result.rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/purchase-installments/:id', authenticate, async (req, res) => {
  try {
    const result = await q('DELETE FROM purchase_installments WHERE id = $1', [req.params.id]);
    res.json({ acknowledged: true, deletedCount: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════
// REPORTS ENDPOINTS
// ═══════════════════════════════════════
app.get('/api/reports/daily', authenticate, async (req, res) => {
  try {
    const sales = await q(`SELECT * FROM sales WHERE date >= date_trunc('day', NOW()) AND date < date_trunc('day', NOW()) + interval '1 day'`);
    const purchases = await q(`SELECT * FROM purchases WHERE date >= date_trunc('day', NOW()) AND date < date_trunc('day', NOW()) + interval '1 day'`);
    const expenses = await q(`SELECT * FROM expenses WHERE date >= date_trunc('day', NOW()) AND date < date_trunc('day', NOW()) + interval '1 day'`);

    const salesRows = sales.rows.map(rowSale);
    const purchaseRows = purchases.rows.map(rowPurchase);
    const expenseRows = expenses.rows.map(rowExpense);
    const totalSales = salesRows.reduce((sum, s) => sum + s.total, 0);          // شامل الضريبة (للعرض)
    const netSales = salesRows.reduce((sum, s) => sum + (s.subtotal || 0), 0);   // صافي قبل الضريبة
    const totalPurchases = purchaseRows.reduce((sum, p) => sum + p.total, 0);
    const cogs = purchaseRows.reduce((sum, p) => sum + (p.subtotal || 0), 0);    // تكلفة البضاعة (صافي)
    const totalExpenses = expenseRows.reduce((sum, e) => sum + (e.amount || 0), 0);
    const grossProfit = netSales - cogs;
    const netProfit = grossProfit - totalExpenses;

    res.json({
      date: new Date(),
      sales: {
        count: salesRows.length,
        total: totalSales,
        paid: salesRows.reduce((sum, s) => sum + s.paid, 0),
        remaining: salesRows.reduce((sum, s) => sum + s.remaining, 0)
      },
      purchases: {
        count: purchaseRows.length,
        total: totalPurchases,
        paid: purchaseRows.reduce((sum, p) => sum + p.paid, 0),
        remaining: purchaseRows.reduce((sum, p) => sum + p.remaining, 0)
      },
      expenses: totalExpenses,
      grossProfit,
      profit: netProfit
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/reports/monthly', authenticate, async (req, res) => {
  try {
    const month = Number(req.query.month ?? new Date().getMonth());
    const year = Number(req.query.year ?? new Date().getFullYear());
    const start = new Date(year, month, 1);
    const end = new Date(year, month + 1, 1);

    const sales = await q('SELECT * FROM sales WHERE date >= $1 AND date < $2', [start, end]);
    const purchases = await q('SELECT * FROM purchases WHERE date >= $1 AND date < $2', [start, end]);
    const expenses = await q('SELECT * FROM expenses WHERE date >= $1 AND date < $2', [start, end]);
    const salesRows = sales.rows.map(rowSale);
    const purchaseRows = purchases.rows.map(rowPurchase);
    const expenseRows = expenses.rows.map(rowExpense);
    const totalSales = salesRows.reduce((sum, s) => sum + s.total, 0);          // شامل الضريبة (للعرض)
    const netSales = salesRows.reduce((sum, s) => sum + (s.subtotal || 0), 0);   // صافي قبل الضريبة
    const totalPurchases = purchaseRows.reduce((sum, p) => sum + p.total, 0);
    const cogs = purchaseRows.reduce((sum, p) => sum + (p.subtotal || 0), 0);    // تكلفة البضاعة (صافي)
    const totalExpenses = expenseRows.reduce((sum, e) => sum + (e.amount || 0), 0);
    const grossProfit = netSales - cogs;
    const netProfit = grossProfit - totalExpenses;

    res.json({
      month,
      year,
      sales: {
        count: salesRows.length,
        total: totalSales,
        paid: salesRows.reduce((sum, s) => sum + s.paid, 0),
        remaining: salesRows.reduce((sum, s) => sum + s.remaining, 0)
      },
      purchases: {
        count: purchaseRows.length,
        total: totalPurchases,
        paid: purchaseRows.reduce((sum, p) => sum + p.paid, 0),
        remaining: purchaseRows.reduce((sum, p) => sum + p.remaining, 0)
      },
      expenses: totalExpenses,
      grossProfit,
      profit: netProfit
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/reports/inventory', authenticate, async (req, res) => {
  try {
    const result = await q('SELECT * FROM products ORDER BY id');
    const products = result.rows.map(rowProduct);
    const totalValue = products.reduce((sum, p) => sum + (p.stock_qty * p.buy_price), 0);
    const lowStock = products.filter(p => p.stock_qty < 10);
    res.json({
      totalProducts: products.length,
      totalQuantity: products.reduce((sum, p) => sum + p.stock_qty, 0),
      totalValue,
      lowStock,
      products
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/data/all', authenticate, async (req, res) => {
  try {
    const state = await getStateMap();
    res.json({
      products: state.bq_products,
      sales: state.bq_sales,
      customers: state.bq_customers,
      suppliers: state.bq_suppliers,
      expenses: state.bq_expenses,
      purchases: state.bq_purchases,
      installments: state.bq_installments,
      employees: state.bq_employees,
      leaves: state.bq_leaves,
      purchaseInstallments: state.bq_pur_inst,
      counters: { invoice: state.bq_inv_counter, quotation: state.bq_qt_counter }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    const uptime = Math.floor(process.uptime());
    const memoryUsage = process.memoryUsage();
    
    return successResponse(res, {
      status: 'OK',
      database: 'PostgreSQL',
      timestamp: new Date(),
      uptime: `${uptime}s`,
      memory: {
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
      }
    }, 'الخادم يعمل بشكل طبيعي');
  } catch (err) {
    logError(err, { context: 'Health Check' });
    return errorResponse(res, 'خطأ في الاتصال بقاعدة البيانات', 503);
  }
});

// ═══════════════════════════════════════
// ERROR HANDLING - معالجة الأخطاء الشاملة
// ═══════════════════════════════════════
// 404 Handler
app.use((req, res) => {
  logger.warn(`404 Not Found: ${req.method} ${req.path}`);
  return errorResponse(res, 'المورد غير موجود (404)', 404);
});

// Global Error Handler
app.use((err, req, res, next) => {
  logError(err, {
    method: req.method,
    path: req.path,
    ip: req.ip,
    url: req.originalUrl
  });

  // معالجة الأخطاء المختلفة
  if (err.message.includes('CORS')) {
    return errorResponse(res, 'خطأ في CORS', 403);
  }

  if (err.message.includes('JSON')) {
    return errorResponse(res, 'بيانات JSON غير صحيحة', 400);
  }

  if (err.statusCode === 429) {
    return errorResponse(res, 'تم تجاوز حد الطلبات، يرجى المحاولة لاحقاً', 429);
  }

  // الخطأ الافتراضي
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'حدث خطأ في الخادم' 
    : err.message;

  return errorResponse(res, message, statusCode);
});

// ═══════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════
async function start() {
  try {
    // اختبار اتصال قاعدة البيانات
    const dbConnected = await testDatabaseConnection();
    if (!dbConnected) {
      throw new Error('فشل الاتصال بقاعدة البيانات');
    }

    // تهيئة قاعدة البيانات إذا لزم الأمر
    await connectDB();

    // تهيئة نظام الـ Cache
    await initCache();

    // تسجيل بدء الخادم
    await logActivity({
      action: 'تشغيل السيرفر',
      user: 'system',
      source: 'server',
      entity: 'system',
      method: 'START',
      statusCode: 200,
      details: {
        port: PORT,
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version,
        timestamp: new Date().toISOString()
      }
    });

    // بدء الخادم
    app.listen(PORT, () => {
      console.log(`
╔════════════════════════════════════════════════════════════╗
║   🛋️  نظام إدارة أثاث بن قزامل - Backend Server          ║
║       Backend Server - PostgreSQL + Redis Cache             ║
╚════════════════════════════════════════════════════════════╝

✅ الخادم يعمل على: http://localhost:${PORT}
✅ API Base: http://localhost:${PORT}/api
✅ الواجهة الرئيسية: http://localhost:${PORT}/index.html✅ لوحة التحكم: http://localhost:${PORT}/admin
✅ قاعدة البيانات: PostgreSQL
✅ بيئة التشغيل: ${process.env.NODE_ENV || 'development'}
✅ الأمان: Helmet + Rate Limiting + CORS
✅ الـ Cache: ${process.env.REDIS_ENABLED === 'true' ? 'Redis Enabled' : 'Disabled'}
✅ Logging: Winston Logger

اضغط Ctrl+C لإيقاف الخادم
      `);

      logger.success(`🚀 النظام جاهز للعمل على البورت ${PORT}`);
    });
  } catch (err) {
    logError(err, { context: 'Server Startup' });
    console.error('❌ فشل في بدء الخادم:', err.message);
    process.exit(1);
  }
}

start();

// ═══════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═══════════════════════════════════════
async function gracefulShutdown() {
  logger.warn('⏹️ تلقي إشارة إيقاف...');

  try {
    // إغلاق اتصالات قاعدة البيانات
    await pool.end();
    logger.info('✅ تم قطع اتصال قاعدة البيانات');

    // إغلاق الـ Cache
    await closeCache();
    logger.info('✅ تم إغلاق Redis Cache');

    // تسجيل الإيقاف
    await logActivity({
      action: 'إيقاف السيرفر',
      user: 'system',
      source: 'server',
      entity: 'system',
      method: 'SHUTDOWN',
      statusCode: 200,
      details: { timestamp: new Date().toISOString() }
    }).catch(() => {});

    logger.success('✅ تم إيقاف الخادم بنجاح');
    process.exit(0);
  } catch (err) {
    logger.error(`❌ خطأ في الإيقاف: ${err.message}`);
    process.exit(1);
  }
}

// معالجات الإشارات
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// معالجة الأخطاء غير المتوقعة
process.on('uncaughtException', (err) => {
  logCritical('Uncaught Exception', { error: err.message, stack: err.stack });
  console.error('❌ خطأ غير متوقع:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logCritical('Unhandled Rejection', { promise: String(promise), reason });
  console.error('❌ رفض غير معالج:', reason);
});
