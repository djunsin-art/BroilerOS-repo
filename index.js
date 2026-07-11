// ============================================================
// BROILEROS BACKEND v2.2 (Render Ready) - REFACTORED
// Perubahan utama dari v2.1:
//  - Middleware (helmet/cors/json) dipindah ke ATAS sebelum semua
//    route didaftarkan. Di v2.1, route /api/admin/global-stats
//    didaftarkan SEBELUM cors()/helmet() terpasang -> preflight
//    OPTIONS request dari browser gagal (404) sehingga fitur
//    Global Stats tidak pernah bisa dipanggil dari frontend.
//  - Route /api/admin/global-stats yang terduplikasi 3x disatukan.
//  - Semua endpoint yang dipanggil index.html tapi belum ada di
//    backend v2.1 (barns, reports, floor-config, water/predict,
//    floor/status, telemetry, sync, dwp/*, feed/*, users CRUD)
//    diimplementasikan sesuai kontrak payload/response frontend.
//  - Role disimpan lowercase di DB, di-normalize ke Capitalized
//    saat dikirim ke frontend (frontend butuh 'Manager', bukan
//    'manager' untuk buildNav/mgrC check) - lihat capRole().
//  - Semua route dibungkus try/catch agar tidak crash & tidak
//    membocorkan stack trace ke klien.
// ============================================================

const dns = require('dns');
dns.setDefaultResultOrder('ipv4first'); // Solusi IPv4 untuk Render + Supabase

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'broileros-super-secret-key';

// ============================================================
// DATABASE CONNECTION
// ============================================================
console.log('🔌 Mencoba koneksi ke database...');
if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL tidak ditemukan di environment variables!');
    console.error('⚠️ Server tetap berjalan, tetapi endpoint database akan error.');
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
        ? false
        : { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message || err);
        console.log('⚠️ Server tetap berjalan tanpa database.');
    } else {
        console.log('✅ Database connected successfully.');
        release();
    }
});

pool.on('error', (err) => {
    console.error('❌ Database error:', err.message);
});

// ============================================================
// GLOBAL MIDDLEWARE (HARUS di atas, sebelum semua route)
// ============================================================
app.use(helmet());

const allowedOrigins = [
    'https://broileros.pages.dev',
    'http://localhost:5173',
    'http://localhost:3000',
    'https://broileros.onrender.com'
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Terlalu banyak percobaan login. Coba lagi 15 menit.' }
});

// ============================================================
// HELPERS
// ============================================================

// Normalisasi role dari DB (lowercase) -> format yang dipakai frontend
function capRole(role) {
    if (!role) return role;
    return role.charAt(0).toUpperCase() + role.slice(1).toLowerCase();
}

function publicUser(row, farmName) {
    return {
        id: row.id,
        name: row.name,
        role: capRole(row.role),
        farm_id: row.farm_id,
        barn_id: row.barn_id,
        floor_id: row.floor_id,
        farm_name: farmName || 'Farm',
        is_super_admin: row.is_super_admin || false
    };
}

// --- Replikasi persis logika risk engine di frontend (index.html) ---
function calculateTHI(t, h) {
    const tf = 1.8 * t + 32;
    return Math.round((tf - (0.55 - 0.0055 * h) * (tf - 58)) * 10) / 10;
}

function getZone(age, thi) {
    const zones = [
        { min: 0, max: 7, comfort: 92, alert: 95 },
        { min: 8, max: 14, comfort: 89, alert: 93 },
        { min: 15, max: 21, comfort: 86, alert: 90 },
        { min: 22, max: 28, comfort: 84, alert: 88 },
        { min: 29, max: 35, comfort: 81, alert: 85 },
        { min: 36, max: 60, comfort: 79, alert: 83 }
    ];
    const z = zones.find(z => age >= z.min && age <= z.max) || zones[zones.length - 1];
    if (thi > z.alert) return 'danger';
    if (thi > z.comfort) return 'alert';
    return 'comfort';
}

function calcRisk(age, thi, zone, mort, pop, wind, wir) {
    let s = 0;
    const zones = { comfort: [0, 10], alert: [10, 30], danger: [30, 40] };
    const [mn, mx] = zones[zone] || zones.comfort;
    s += mn + (mx - mn) * ((thi % 10) / 10);
    const mr = pop > 0 ? (mort / pop) * 100 : 0;
    if (mr > 0.5) s += 30;
    else if (mr > 0.2) s += 20;
    else if (mr > 0.05) s += 10;
    if (wind < 1) s += 15;
    else if (wind < 1.5) s += 10;
    else if (wind < 2) s += 5;
    const ref = { lo: 1.5, hi: 3.0 };
    if (age <= 7) { ref.lo = 1.5; ref.hi = 2.0; }
    else if (age <= 14) { ref.lo = 1.7; ref.hi = 2.2; }
    else if (age <= 21) { ref.lo = 1.8; ref.hi = 2.3; }
    else if (age <= 28) { ref.lo = 1.9; ref.hi = 2.5; }
    else if (age <= 35) { ref.lo = 2.0; ref.hi = 2.8; }
    else { ref.lo = 2.0; ref.hi = 3.0; }
    if (wir > ref.hi + 0.5) s += 10;
    else if (wir > ref.hi) s += 6;
    if (age >= 14 && age <= 28) s += 5;
    else if (age >= 7 && age <= 35) s += 3;
    else s += 1;
    return Math.min(100, Math.round(s));
}

function getLevel(s) {
    if (s < 25) return 'RENDAH';
    if (s < 50) return 'SEDANG';
    if (s < 75) return 'TINGGI';
    return 'KRITIS';
}

function dwpPhaseFor(age, zone) {
    if (age <= 3) return 'DWP-START DOC';
    if (zone === 'danger') return 'DWP-HA';
    return 'DWP-BASE ECO';
}

// Kurva referensi water intake (ml/ekor/hari) dipakai sebagai fallback
// jika sebuah floor belum punya baseline sendiri di tabel water_baselines.
// Nilai sama dengan seed Lantai 1 (Ross 308 reference).
const DEFAULT_WATER_CURVE = [
    { age_days: 1, baseline_ml_per_bird: 68 },
    { age_days: 7, baseline_ml_per_bird: 116 },
    { age_days: 14, baseline_ml_per_bird: 175 },
    { age_days: 21, baseline_ml_per_bird: 222 },
    { age_days: 28, baseline_ml_per_bird: 268 },
    { age_days: 35, baseline_ml_per_bird: 315 },
    { age_days: 42, baseline_ml_per_bird: 435 }
];

function interpolateBaseline(points, age) {
    const sorted = [...points].sort((a, b) => a.age_days - b.age_days);
    if (age <= sorted[0].age_days) return sorted[0].baseline_ml_per_bird;
    if (age >= sorted[sorted.length - 1].age_days) return sorted[sorted.length - 1].baseline_ml_per_bird;
    for (let i = 0; i < sorted.length - 1; i++) {
        const a = sorted[i], b = sorted[i + 1];
        if (age >= a.age_days && age <= b.age_days) {
            const frac = (age - a.age_days) / (b.age_days - a.age_days);
            return a.baseline_ml_per_bird + frac * (b.baseline_ml_per_bird - a.baseline_ml_per_bird);
        }
    }
    return sorted[sorted.length - 1].baseline_ml_per_bird;
}

// Prediksi konsumsi air. Konstanta modifier (temp/hum/wind) adalah
// estimasi rekayasa awal (belum divalidasi trial lapangan) - HEMITA
// disarankan mengkalibrasi ulang begitu data Trial 1 (D4-D14) tersedia.
async function predictWater(floorId, ageDays, temperature, humidity, windSpeed, population) {
    const baseRes = await pool.query(
        'SELECT age_days, baseline_ml_per_bird FROM water_baselines WHERE floor_id = $1 ORDER BY age_days',
        [floorId]
    );
    // PENTING: kolom DECIMAL dikembalikan sebagai STRING oleh driver `pg`
    // (bukan number) untuk menghindari kehilangan presisi. Harus di-cast
    // eksplisit ke Number di sini, kalau tidak operator '+' di
    // interpolateBaseline() akan melakukan string concatenation, bukan
    // penjumlahan matematis (bug nyata yang ketahuan saat diuji live).
    const rawPoints = baseRes.rows.length > 0 ? baseRes.rows : DEFAULT_WATER_CURVE;
    const points = rawPoints.map(p => ({
        age_days: Number(p.age_days),
        baseline_ml_per_bird: Number(p.baseline_ml_per_bird)
    }));
    const baselineMl = interpolateBaseline(points, ageDays);

    const t = temperature ?? 28;
    const h = humidity ?? 70;
    const w = windSpeed ?? 2;

    const tempFactor = 1 + Math.max(0, t - 26) * 0.04;      // +4%/°C di atas 26°C
    const humFactor = 1 + Math.max(0, h - 70) * 0.005;      // +0.5%/%RH di atas 70%
    const windFactor = 1 - Math.min(0.15, Math.max(0, w - 1) * 0.03); // efek pendinginan tunnel

    const expectedLiters = (population * baselineMl * tempFactor * humFactor * windFactor) / 1000;

    let config = { elevation: 0, roof: 'metal' };
    try {
        const cfgRes = await pool.query('SELECT elevation_meters, roof_type FROM floor_configs WHERE floor_id = $1', [floorId]);
        if (cfgRes.rows.length > 0) {
            config = { elevation: Number(cfgRes.rows[0].elevation_meters) || 0, roof: cfgRes.rows[0].roof_type || 'metal' };
        }
    } catch (e) { /* pakai default kalau gagal */ }

    return {
        expected_liters: Math.round(expectedLiters * 100) / 100,
        baseline_ml_per_bird: Math.round(baselineMl * 100) / 100,
        modifiers: {
            temp: Math.round(tempFactor * 1000) / 1000,
            hum: Math.round(humFactor * 1000) / 1000,
            windFactor: Math.round(windFactor * 1000) / 1000
        },
        config
    };
}

// Pilih produk DWP sesuai umur/kondisi (mengikuti protokol 3-SKU HEMITA)
async function pickDwpProduct(ageDays, zone) {
    const sku = ageDays <= 3 ? 'DWPSD' : (zone === 'danger' ? 'DWPH-A' : 'DWPBE');
    const res = await pool.query('SELECT * FROM dwp_products WHERE sku = $1 AND is_active = true', [sku]);
    if (res.rows.length > 0) return res.rows[0];
    // fallback kalau SKU tak ditemukan (mis. data belum di-seed)
    const fallback = await pool.query('SELECT * FROM dwp_products WHERE is_active = true ORDER BY created_at LIMIT 1');
    return fallback.rows[0] || null;
}

function calcDwpDose(product, estimatedWaterLiters) {
    const totalGrams = Math.round((product.grams_per_1000l * estimatedWaterLiters) / 1000 * 100) / 100;
    const packages = Math.max(1, Math.ceil(totalGrams / product.package_size_grams));
    const totalPrice = packages * parseFloat(product.price_per_package);
    return { totalGrams, packages, totalPrice };
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
async function auth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query(
            'SELECT id, name, role, farm_id, barn_id, floor_id, is_super_admin FROM users WHERE id = $1 AND active = true',
            [decoded.id]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = result.rows[0];
        req.isSuperAdmin = req.user.is_super_admin || false;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function requireManager(req, res, next) {
    if (req.isSuperAdmin || (req.user.role || '').toLowerCase() === 'manager') return next();
    return res.status(403).json({ error: 'Akses khusus Manager' });
}

// ============================================================
// ROUTES: HEALTH / MISC
// ============================================================
app.get('/', (req, res) => res.send('BroilerOS Backend is running!'));

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.get('/test-db', async (req, res) => {
    try {
        if (!process.env.DATABASE_URL) {
            return res.status(500).json({ success: false, error: 'DATABASE_URL is not set in environment variables' });
        }
        const result = await pool.query('SELECT NOW()');
        res.json({ success: true, time: result.rows[0].now, db_url_set: !!process.env.DATABASE_URL });
    } catch (err) {
        console.error('Test DB error:', err);
        res.status(500).json({ success: false, error: err.message || 'Unknown error' });
    }
});

// ============================================================
// AUTH
// ============================================================
app.get('/api/users/public', async (req, res) => {
    try {
        const { role } = req.query;
        let query = 'SELECT id, name, role FROM users WHERE active = true';
        const params = [];
        if (role) { query += ' AND LOWER(role) = LOWER($1)'; params.push(role); }
        query += ' ORDER BY name';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('users/public error:', err);
        res.status(500).json({ error: 'Gagal mengambil daftar user' });
    }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { userId, pin } = req.body;
        if (!userId || !pin) return res.status(400).json({ error: 'User ID dan PIN wajib' });
        if (!userId.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
            return res.status(400).json({ error: 'Format User ID tidak valid' });
        }
        if (!pin.match(/^[0-9]{4,6}$/)) return res.status(400).json({ error: 'PIN harus 4-6 digit angka' });

        const result = await pool.query('SELECT * FROM users WHERE id = $1 AND active = true', [userId]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'User tidak ditemukan' });
        const user = result.rows[0];
        const valid = await bcrypt.compare(pin, user.pin_hash);
        if (!valid) return res.status(401).json({ error: 'PIN salah' });

        const farm = await pool.query('SELECT name FROM farms WHERE id = $1', [user.farm_id]);
        const token = jwt.sign({ id: user.id, role: user.role, farm_id: user.farm_id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: publicUser(user, farm.rows[0]?.name) });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Gagal login', detail: err.message });
    }
});

// ============================================================
// ADMIN SETUP (SUPER ADMIN) - dijalankan sekali di awal deployment
// ============================================================
app.post('/api/admin/setup', async (req, res) => {
    try {
        const { name, pin, farmName } = req.body;
        if (!name || !pin) return res.status(400).json({ error: 'Name dan PIN wajib' });

        const existing = await pool.query('SELECT id FROM users WHERE is_super_admin = true LIMIT 1');
        if (existing.rows.length > 0) return res.status(400).json({ error: 'Super Admin sudah ada.' });

        const hash = await bcrypt.hash(pin, 10);
        let farmId;
        const farmRes = await pool.query('SELECT id FROM farms LIMIT 1');
        if (farmRes.rows.length === 0) {
            const newFarm = await pool.query('INSERT INTO farms (name, owner_name) VALUES ($1, $2) RETURNING id', [farmName || 'Hemita Farm', name]);
            farmId = newFarm.rows[0].id;
        } else {
            farmId = farmRes.rows[0].id;
        }

        const result = await pool.query(
            'INSERT INTO users (name, pin_hash, role, farm_id, is_super_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [name, hash, 'manager', farmId, true]
        );
        res.status(201).json({ message: 'Super Admin created!', id: result.rows[0].id });
    } catch (err) {
        console.error('Admin setup error:', err);
        res.status(500).json({ error: 'Gagal membuat super admin', detail: err.message });
    }
});

// ============================================================
// GLOBAL STATS (Super Admin Only)
// ============================================================
app.get('/api/admin/global-stats', auth, async (req, res) => {
    if (!req.isSuperAdmin) {
        return res.status(403).json({ error: 'Akses khusus Super Admin' });
    }
    try {
        const totalFarms = await pool.query('SELECT COUNT(*) FROM farms');
        const totalBarns = await pool.query('SELECT COUNT(*) FROM barns');
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users WHERE active = true');
        const totalReports = await pool.query('SELECT COUNT(*) FROM telemetry_reports');
        const avgRisk = await pool.query('SELECT AVG(risk_score) FROM telemetry_reports');
        const topRisks = await pool.query(`
            SELECT r.*, f.name as farm_name, u.name as user_name, b.name as barn_name, fl.name as floor_name
            FROM telemetry_reports r
            JOIN farms f ON r.farm_id = f.id
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN barns b ON r.barn_id = b.id
            LEFT JOIN floors fl ON r.floor_id = fl.id
            ORDER BY r.risk_score DESC LIMIT 10
        `);

        res.json({
            totalFarms: parseInt(totalFarms.rows[0].count),
            totalBarns: parseInt(totalBarns.rows[0].count),
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalReports: parseInt(totalReports.rows[0].count),
            avgRisk: parseFloat(avgRisk.rows[0].avg) || 0,
            topRisks: topRisks.rows
        });
    } catch (err) {
        console.error('Global stats error:', err);
        res.status(500).json({ error: 'Gagal mengambil data global', detail: err.message });
    }
});

// ============================================================
// BARNS & FLOORS
// ============================================================
app.get('/api/barns', auth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT b.*,
                COALESCE(
                    json_agg(
                        json_build_object(
                            'id', f.id, 'name', f.name, 'floor_number', f.floor_number,
                            'default_population', f.default_population, 'default_density', f.default_density
                        ) ORDER BY f.floor_number
                    ) FILTER (WHERE f.id IS NOT NULL), '[]'
                ) as floors
            FROM barns b
            LEFT JOIN floors f ON f.barn_id = b.id
            WHERE b.farm_id = $1
            GROUP BY b.id
            ORDER BY b.name
        `, [req.user.farm_id]);
        res.json(result.rows);
    } catch (err) {
        console.error('barns error:', err);
        res.status(500).json({ error: 'Gagal mengambil data kandang' });
    }
});

// ============================================================
// FLOOR CONFIG
// ============================================================
app.get('/api/floors/:id/config', auth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM floor_configs WHERE floor_id = $1', [req.params.id]);
        if (result.rows.length === 0) {
            return res.json({
                elevation_meters: 0, roof_type: 'metal',
                nipple_flow_rate: 90, water_pressure: 3.5,
                meta_data: { electrical: { phase: '3 phase 380V' } }
            });
        }
        const row = result.rows[0];
        res.json({
            elevation_meters: row.elevation_meters,
            roof_type: row.roof_type,
            nipple_flow_rate: row.nipple_flow_rate_ml_min,
            water_pressure: row.water_pressure_psi,
            meta_data: row.meta_data
        });
    } catch (err) {
        console.error('floor config get error:', err);
        res.status(500).json({ error: 'Gagal mengambil konfigurasi lantai' });
    }
});

app.post('/api/floors/:id/config', auth, requireManager, async (req, res) => {
    try {
        const floorId = req.params.id;
        const { elevation_meters, roof_type, nipple_flow_rate_ml_min, water_pressure_psi, meta_data } = req.body;
        const result = await pool.query(`
            INSERT INTO floor_configs (floor_id, elevation_meters, roof_type, nipple_flow_rate_ml_min, water_pressure_psi, meta_data, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (floor_id) DO UPDATE SET
                elevation_meters = EXCLUDED.elevation_meters,
                roof_type = EXCLUDED.roof_type,
                nipple_flow_rate_ml_min = EXCLUDED.nipple_flow_rate_ml_min,
                water_pressure_psi = EXCLUDED.water_pressure_psi,
                meta_data = EXCLUDED.meta_data,
                updated_at = NOW()
            RETURNING *
        `, [floorId, elevation_meters || 0, roof_type || 'metal', nipple_flow_rate_ml_min || 90, water_pressure_psi || 3.5, meta_data || {}]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error('floor config save error:', err);
        res.status(500).json({ error: 'Gagal menyimpan konfigurasi lantai', detail: err.message });
    }
});

// ============================================================
// WATER INTELLIGENCE
// ============================================================
app.post('/api/water/predict', auth, async (req, res) => {
    try {
        const { floorId, ageDays, temperature, humidity, windSpeed, population } = req.body;
        if (!floorId || !ageDays || !population) {
            return res.status(400).json({ error: 'floorId, ageDays, population wajib diisi' });
        }
        const prediction = await predictWater(floorId, ageDays, temperature, humidity, windSpeed, population);
        res.json(prediction);
    } catch (err) {
        console.error('water predict error:', err);
        res.status(500).json({ error: 'Gagal memprediksi konsumsi air', detail: err.message });
    }
});

// ============================================================
// FLOOR DAILY STATUS (Populasi)
// ============================================================
app.post('/api/floor/status', auth, async (req, res) => {
    try {
        const { floorId, ageDays, populationStart, mortalityToday, culledToday, soldToday,
            avgWeightKg, fcr, notes, causeCategory } = req.body;
        if (!floorId) return res.status(400).json({ error: 'floorId wajib diisi' });

        const popEnd = Math.max(0, (populationStart || 0) - (mortalityToday || 0) - (culledToday || 0) - (soldToday || 0));
        const totalWeightKg = Math.round(popEnd * (avgWeightKg || 0) * 100) / 100;

        const result = await pool.query(`
            INSERT INTO floor_daily_status
                (floor_id, report_date, age_days, population_start, mortality_today, culled_today, sold_today,
                 population_end, avg_weight_kg, total_weight_kg, feed_conversion_ratio, notes, cause_category, created_by)
            VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (floor_id, report_date) DO UPDATE SET
                age_days = EXCLUDED.age_days,
                population_start = EXCLUDED.population_start,
                mortality_today = EXCLUDED.mortality_today,
                culled_today = EXCLUDED.culled_today,
                sold_today = EXCLUDED.sold_today,
                population_end = EXCLUDED.population_end,
                avg_weight_kg = EXCLUDED.avg_weight_kg,
                total_weight_kg = EXCLUDED.total_weight_kg,
                feed_conversion_ratio = EXCLUDED.feed_conversion_ratio,
                notes = EXCLUDED.notes,
                cause_category = EXCLUDED.cause_category,
                updated_at = NOW()
            RETURNING *
        `, [floorId, ageDays, populationStart, mortalityToday || 0, culledToday || 0, soldToday || 0,
            popEnd, avgWeightKg || 0, totalWeightKg, fcr || null, notes || null, causeCategory || null, req.user.id]);

        res.json(result.rows[0]);
    } catch (err) {
        console.error('floor status error:', err);
        res.status(500).json({ error: 'Gagal menyimpan status populasi', detail: err.message });
    }
});

// ============================================================
// TELEMETRY
// ============================================================
async function insertTelemetry(payload, userId) {
    const { barnId, floorId, ageDays, temperature, humidity, mortality, windSpeed,
        waterConsumption, feedConsumption, population } = payload;

    const floorRes = await pool.query('SELECT b.farm_id FROM floors f JOIN barns b ON f.barn_id = b.id WHERE f.id = $1', [floorId]);
    if (floorRes.rows.length === 0) throw new Error('Floor tidak ditemukan');
    const farmId = floorRes.rows[0].farm_id;

    const thi = calculateTHI(temperature, humidity);
    const zone = getZone(ageDays, thi);
    const wir = feedConsumption > 0 ? waterConsumption / feedConsumption : 0;
    const riskScore = calcRisk(ageDays, thi, zone, mortality, population, windSpeed, wir);
    const riskLevel = getLevel(riskScore);
    const heatStress = zone === 'danger';
    const dwpPhase = dwpPhaseFor(ageDays, zone);

    const result = await pool.query(`
        INSERT INTO telemetry_reports
            (farm_id, barn_id, floor_id, user_id, age_days, population, temperature, humidity, mortality,
             wind_speed, water_consumption, feed_consumption, thi, thi_zone, wir, risk_score, risk_level,
             heat_stress, dwp_phase)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        RETURNING *
    `, [farmId, barnId, floorId, userId, ageDays, population, temperature, humidity, mortality || 0,
        windSpeed, waterConsumption || 0, feedConsumption || 0, thi, zone, Math.round(wir * 1000) / 1000,
        riskScore, riskLevel, heatStress, dwpPhase]);

    return result.rows[0];
}

app.post('/api/telemetry', auth, async (req, res) => {
    try {
        const row = await insertTelemetry(req.body, req.user.id);
        res.status(201).json(row);
    } catch (err) {
        console.error('telemetry error:', err);
        res.status(500).json({ error: 'Gagal menyimpan telemetri', detail: err.message });
    }
});

app.get('/api/reports', auth, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 100, 500);
        const result = await pool.query(`
            SELECT r.*, u.name as user_name
            FROM telemetry_reports r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.farm_id = $1
            ORDER BY r.created_at DESC
            LIMIT $2
        `, [req.user.farm_id, limit]);
        res.json(result.rows);
    } catch (err) {
        console.error('reports error:', err);
        res.status(500).json({ error: 'Gagal mengambil laporan' });
    }
});

// ============================================================
// SYNC ENGINE (offline queue -> server)
// ============================================================
app.post('/api/sync', auth, async (req, res) => {
    const { queue } = req.body;
    if (!Array.isArray(queue)) return res.status(400).json({ error: 'queue harus berupa array' });

    const results = [];
    for (const item of queue) {
        try {
            if (item.table === 'telemetry_reports') {
                await insertTelemetry(item.payload, req.user.id);
            } else if (item.table === 'floor_daily_status') {
                const p = item.payload;
                const popEnd = Math.max(0, (p.populationStart || 0) - (p.mortalityToday || 0) - (p.culledToday || 0) - (p.soldToday || 0));
                const totalWeightKg = Math.round(popEnd * (p.avgWeightKg || 0) * 100) / 100;
                await pool.query(`
                    INSERT INTO floor_daily_status
                        (floor_id, report_date, age_days, population_start, mortality_today, culled_today, sold_today,
                         population_end, avg_weight_kg, total_weight_kg, feed_conversion_ratio, notes, cause_category, created_by)
                    VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    ON CONFLICT (floor_id, report_date) DO UPDATE SET
                        age_days = EXCLUDED.age_days, population_start = EXCLUDED.population_start,
                        mortality_today = EXCLUDED.mortality_today, culled_today = EXCLUDED.culled_today,
                        sold_today = EXCLUDED.sold_today, population_end = EXCLUDED.population_end,
                        avg_weight_kg = EXCLUDED.avg_weight_kg, total_weight_kg = EXCLUDED.total_weight_kg,
                        feed_conversion_ratio = EXCLUDED.feed_conversion_ratio, notes = EXCLUDED.notes,
                        cause_category = EXCLUDED.cause_category, updated_at = NOW()
                `, [p.floorId, p.ageDays, p.populationStart, p.mortalityToday || 0, p.culledToday || 0, p.soldToday || 0,
                    popEnd, p.avgWeightKg || 0, totalWeightKg, p.fcr || null, p.notes || null, p.causeCategory || null, req.user.id]);
            } else {
                throw new Error(`Tabel tidak dikenal: ${item.table}`);
            }
            results.push({ id: item.id, success: true });
        } catch (e) {
            console.error('sync item failed:', item.id, e.message);
            results.push({ id: item.id, success: false, error: e.message });
        }
    }
    res.json({ results });
});

// ============================================================
// DWP PLANNER
// ============================================================
app.post('/api/dwp/calculate', auth, async (req, res) => {
    try {
        const { floorId, ageDays, totalBirds, estimatedWaterLiters } = req.body;
        if (!floorId || !totalBirds) return res.status(400).json({ error: 'floorId dan totalBirds wajib diisi' });

        let waterLiters = estimatedWaterLiters;
        if (!waterLiters) {
            const pred = await predictWater(floorId, ageDays, 28, 70, 2, totalBirds);
            waterLiters = pred.expected_liters;
        }

        const zone = getZone(ageDays, calculateTHI(28, 70));
        const product = await pickDwpProduct(ageDays, zone);
        if (!product) return res.status(404).json({ error: 'Produk DWP tidak ditemukan' });

        const dose = calcDwpDose(product, waterLiters);
        res.json({
            products: [{ product, totalGrams: dose.totalGrams, packages: dose.packages }],
            totalPrice: dose.totalPrice,
            estimatedWaterLiters: waterLiters
        });
    } catch (err) {
        console.error('dwp calculate error:', err);
        res.status(500).json({ error: 'Gagal menghitung DWP', detail: err.message });
    }
});

app.post('/api/dwp/order', auth, requireManager, async (req, res) => {
    try {
        const { floorId, ageDays, totalBirds } = req.body;
        if (!floorId || !totalBirds) return res.status(400).json({ error: 'floorId dan totalBirds wajib diisi' });

        const pred = await predictWater(floorId, ageDays, 28, 70, 2, totalBirds);
        const zone = getZone(ageDays, calculateTHI(28, 70));
        const product = await pickDwpProduct(ageDays, zone);
        if (!product) return res.status(404).json({ error: 'Produk DWP tidak ditemukan' });
        const dose = calcDwpDose(product, pred.expected_liters);

        const result = await pool.query(`
            INSERT INTO dwp_prescriptions
                (floor_id, product_id, age_days, total_birds, estimated_water_liters,
                 required_product_units, required_packages, total_price, status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending')
            RETURNING *
        `, [floorId, product.id, ageDays, totalBirds, pred.expected_liters, dose.totalGrams, dose.packages, dose.totalPrice]);

        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('dwp order error:', err);
        res.status(500).json({ error: 'Gagal membuat pesanan DWP', detail: err.message });
    }
});

// ============================================================
// FEED MANAGEMENT
// ============================================================
app.get('/api/feed/inventory/:floorId', auth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feed_inventory WHERE floor_id = $1', [req.params.floorId]);
        res.json(result.rows[0] || { floor_id: req.params.floorId, current_stock_kg: 0 });
    } catch (err) {
        console.error('feed inventory error:', err);
        res.status(500).json({ error: 'Gagal mengambil stok pakan' });
    }
});

app.post('/api/feed/receipt', auth, requireManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { floorId, quantityKg, feedType, supplier } = req.body;
        if (!floorId || !quantityKg || quantityKg <= 0) return res.status(400).json({ error: 'Data tidak valid' });

        await client.query('BEGIN');
        const receipt = await client.query(`
            INSERT INTO feed_receipts (floor_id, received_date, quantity_kg, feed_type, supplier, created_by)
            VALUES ($1, CURRENT_DATE, $2, $3, $4, $5) RETURNING *
        `, [floorId, quantityKg, feedType || null, supplier || null, req.user.id]);

        await client.query(`
            INSERT INTO feed_inventory (floor_id, current_stock_kg, last_updated)
            VALUES ($1, $2, NOW())
            ON CONFLICT (floor_id) DO UPDATE SET
                current_stock_kg = feed_inventory.current_stock_kg + EXCLUDED.current_stock_kg,
                last_updated = NOW()
        `, [floorId, quantityKg]);

        await client.query('COMMIT');
        res.status(201).json(receipt.rows[0]);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('feed receipt error:', err);
        res.status(500).json({ error: 'Gagal mencatat penerimaan pakan', detail: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/feed/transfer', auth, requireManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { fromFloorId, toFloorId, quantityKg, reason } = req.body;
        if (!fromFloorId || !toFloorId || !quantityKg || quantityKg <= 0) {
            return res.status(400).json({ error: 'Data tidak valid' });
        }
        if (fromFloorId === toFloorId) return res.status(400).json({ error: 'Tidak bisa transfer ke lantai yang sama' });

        await client.query('BEGIN');

        const stockRes = await client.query('SELECT current_stock_kg FROM feed_inventory WHERE floor_id = $1 FOR UPDATE', [fromFloorId]);
        const currentStock = stockRes.rows[0]?.current_stock_kg || 0;
        if (currentStock < quantityKg) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: `Stok tidak cukup (tersedia ${currentStock} kg)` });
        }

        const transfer = await client.query(`
            INSERT INTO feed_transfers (from_floor_id, to_floor_id, transfer_date, quantity_kg, reason, created_by)
            VALUES ($1, $2, CURRENT_DATE, $3, $4, $5) RETURNING *
        `, [fromFloorId, toFloorId, quantityKg, reason || null, req.user.id]);

        await client.query('UPDATE feed_inventory SET current_stock_kg = current_stock_kg - $1, last_updated = NOW() WHERE floor_id = $2', [quantityKg, fromFloorId]);
        await client.query(`
            INSERT INTO feed_inventory (floor_id, current_stock_kg, last_updated)
            VALUES ($1, $2, NOW())
            ON CONFLICT (floor_id) DO UPDATE SET
                current_stock_kg = feed_inventory.current_stock_kg + EXCLUDED.current_stock_kg,
                last_updated = NOW()
        `, [toFloorId, quantityKg]);

        await client.query('COMMIT');
        res.status(201).json(transfer.rows[0]);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('feed transfer error:', err);
        res.status(500).json({ error: 'Gagal mencatat mutasi pakan', detail: err.message });
    } finally {
        client.release();
    }
});

// ============================================================
// USER MANAGEMENT (CRUD) - Manager only
// ============================================================
app.get('/api/users', auth, requireManager, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, role, barn_id, floor_id, active, last_login_at FROM users WHERE farm_id = $1 AND active = true ORDER BY name',
            [req.user.farm_id]
        );
        res.json(result.rows.map(u => ({ ...u, role: capRole(u.role) })));
    } catch (err) {
        console.error('users list error:', err);
        res.status(500).json({ error: 'Gagal mengambil daftar user' });
    }
});

app.post('/api/users', auth, requireManager, async (req, res) => {
    try {
        const { name, pin, role, barnId, floorId } = req.body;
        if (!name || !pin || !role) return res.status(400).json({ error: 'Nama, PIN, dan role wajib diisi' });
        if (!pin.match(/^[0-9]{4,6}$/)) return res.status(400).json({ error: 'PIN harus 4-6 digit angka' });

        const hash = await bcrypt.hash(pin, 10);
        const result = await pool.query(`
            INSERT INTO users (name, pin_hash, role, farm_id, barn_id, floor_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, role, barn_id, floor_id
        `, [name, hash, role.toLowerCase(), req.user.farm_id, barnId || null, floorId || null]);

        res.status(201).json({ ...result.rows[0], role: capRole(result.rows[0].role) });
    } catch (err) {
        console.error('user create error:', err);
        res.status(500).json({ error: 'Gagal membuat user', detail: err.message });
    }
});

app.delete('/api/users/:id', auth, requireManager, async (req, res) => {
    try {
        if (req.params.id === req.user.id) {
            return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
        }
        // Soft delete (bukan hard DELETE) karena user_id direferensikan oleh
        // telemetry_reports/floor_daily_status/feed_receipts/feed_transfers
        // tanpa ON DELETE CASCADE - hard delete akan gagal karena FK constraint.
        const result = await pool.query('UPDATE users SET active = false, updated_at = NOW() WHERE id = $1 AND farm_id = $2 RETURNING id', [req.params.id, req.user.farm_id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User tidak ditemukan' });
        res.json({ success: true });
    } catch (err) {
        console.error('user delete error:', err);
        res.status(500).json({ error: 'Gagal menghapus user', detail: err.message });
    }
});

// ============================================================
// 404 & ERROR HANDLER
// ============================================================
app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan internal server' });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 BroilerOS Backend running on port ${PORT}`);
    console.log(`📡 Health: /api/health`);
    console.log(`📡 Test DB: /test-db`);
});
