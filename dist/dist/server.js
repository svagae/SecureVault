"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const mongoose_1 = __importDefault(require("mongoose"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const cors_1 = __importDefault(require("cors"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const express_rate_limit_1 = require("express-rate-limit");
const http_1 = require("http");
const ws_1 = require("ws");
const mongoose_2 = require("mongoose");
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const geoip_lite_1 = __importDefault(require("geoip-lite"));
const app = (0, express_1.default)();
const ip = process.env.TEST_IP || '203.0.113.5'; // Test IP
const server = new http_1.Server(app);
const wss = new ws_1.Server({ server });
const getClientIp = (req) => {
    var _a;
    return ((_a = req.headers['x-forwarded-for']) === null || _a === void 0 ? void 0 : _a.toString().split(',')[0]) || req.ip || 'unknown';
};
app.use((0, cors_1.default)({ origin: 'http://localhost:5173', credentials: true }));
app.set('trust proxy', 1);
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
app.use((0, express_rate_limit_1.rateLimit)({
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.',
}));
mongoose_1.default.connect('mongodb://localhost:27017/securevault').then(() => console.log('MongoDB connected'));
const userSchema = new mongoose_2.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    consent: { type: Boolean, default: true },
});
const User = (0, mongoose_2.model)('User', userSchema);
const auditLogSchema = new mongoose_2.Schema({
    userId: { type: mongoose_2.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    ip: { type: String },
    country: { type: String },
    device: { type: String },
    icon: { type: String },
    text: { type: String },
    color: { type: String },
});
const AuditLog = (0, mongoose_2.model)('AuditLog', auditLogSchema);
const resetTokenSchema = new mongoose_2.Schema({
    userId: { type: mongoose_2.Schema.Types.ObjectId, ref: 'User' },
    token: { type: String, required: true },
    expires: { type: Date, required: true },
});
const ResetToken = (0, mongoose_2.model)('ResetToken', resetTokenSchema);
const refreshTokenSchema = new mongoose_2.Schema({
    userId: { type: mongoose_2.Schema.Types.ObjectId, ref: 'User' },
    token: { type: String, required: true },
    expires: { type: Date, required: true },
});
const RefreshToken = (0, mongoose_2.model)('RefreshToken', refreshTokenSchema);
const authMiddleware = (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) {
        res.status(401).json({ error: 'No token provided' });
        return;
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, 'this_is_a_secret_key');
        req.userId = decoded.userId;
        next();
    }
    catch (error) {
        res.status(401).json({ error: 'Invalid token' });
        return;
    }
};
const failedLoginAttempts = new Map();
const loginHistory = new Map();
const deviceHistory = new Map();
setInterval(() => {
    var _a, _b, _c, _d;
    const now = Date.now();
    for (const [key] of failedLoginAttempts) {
        const loginData = loginHistory.get(key);
        if (loginData && now - ((_b = (_a = loginData.timestamp) === null || _a === void 0 ? void 0 : _a.getTime()) !== null && _b !== void 0 ? _b : 0) > 24 * 60 * 60 * 1000) {
            failedLoginAttempts.delete(key);
        }
    }
    for (const [key] of loginHistory) {
        const loginData = loginHistory.get(key);
        if (loginData && now - ((_d = (_c = loginData.timestamp) === null || _c === void 0 ? void 0 : _c.getTime()) !== null && _d !== void 0 ? _d : 0) > 24 * 60 * 60 * 1000) {
            loginHistory.delete(key);
        }
    }
}, 24 * 60 * 60 * 1000);
wss.on('connection', (ws) => {
    ws.on('message', (message) => console.log('Received:', message));
    ws.on('close', () => console.log('Client disconnected'));
});
const broadcastEvent = (event) => {
    wss.clients.forEach((client) => {
        if (client.readyState === 1)
            client.send(JSON.stringify(event));
    });
};
const generateThreatEvent = (userId, action, ip, geo, email, device) => {
    var _a;
    const events = [];
    const userKey = `${ip}-${email}`;
    const now = new Date();
    const hour = now.getHours();
    const country = (geo === null || geo === void 0 ? void 0 : geo.country) || 'unknown';
    if (action === 'User logged in') {
        events.push({ icon: '🛡️', text: `Login from ${country}`, time: now.toLocaleTimeString(), color: 'violet', ip: ip || 'unknown', country });
        if (hour < 9 || hour >= 21) {
            events.push({ icon: '⚠️', text: `Unusual login time at ${now.toLocaleTimeString()}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
        }
        const lastDevice = deviceHistory.get(userId);
        if (lastDevice && lastDevice !== device) {
            events.push({ icon: '⚠️', text: `New device detected: ${device}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
        }
        deviceHistory.set(userId, device);
    }
    const attemptCount = (_a = failedLoginAttempts.get(userKey)) !== null && _a !== void 0 ? _a : 0;
    if (attemptCount >= 3) {
        events.push({ icon: '⚠️', text: `Multiple failed logins from ${ip}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
    }
    const prevLogin = loginHistory.get(userKey);
    if (prevLogin && prevLogin.country !== country) {
        events.push({ icon: '⚠️', text: `Geo-switch from ${prevLogin.country} to ${country}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
    }
    events.forEach((event) => {
        AuditLog.create(Object.assign({ userId, action: 'Threat Event' }, event));
        broadcastEvent(Object.assign(Object.assign({ type: 'threat' }, event), { userId }));
    });
};
app.post('/api/register', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password, consent } = req.body;
    if (!email || !password || consent === undefined)
        return res.status(400).json({ error: 'Email, password and consent are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Invalid email format' });
    if (!consent)
        return res.status(400).json({ error: 'Consent required for data processing' });
    try {
        const hashedPassword = yield bcryptjs_1.default.hash(password, 12);
        const user = new User({ email, password: hashedPassword, consent });
        yield user.save();
        const ip = req.ip || 'unknown';
        const geo = geoip_lite_1.default.lookup(ip) || { country: 'unknown' };
        yield AuditLog.create({ userId: user._id, action: 'User registered', ip, country: geo.country });
        broadcastEvent({ type: 'log', action: 'User registered', email, country: geo.country });
        res.status(201).json({ message: 'User registered successfully' });
    }
    catch (err) {
        res.status(400).json({ error: 'Registration failed' });
    }
})));
app.post('/api/login', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email and password are required' });
    const ip = getClientIp(req);
    const geo = geoip_lite_1.default.lookup(ip) || { country: 'unknown' };
    const userKey = `${ip}-${email}`;
    const device = req.get('User-Agent') || 'unknown';
    const user = yield User.findOne({ email });
    if (!user) {
        failedLoginAttempts.set(userKey, ((_a = failedLoginAttempts.get(userKey)) !== null && _a !== void 0 ? _a : 0) + 1);
        if (((_b = failedLoginAttempts.get(userKey)) !== null && _b !== void 0 ? _b : 0) >= 3) {
            broadcastEvent({ type: 'alert', message: 'Multiple failed logins detected', email, ip: ip || 'unknown', country: geo.country || 'unknown' });
        }
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (!(yield bcryptjs_1.default.compare(password, user.password))) {
        failedLoginAttempts.set(userKey, ((_c = failedLoginAttempts.get(userKey)) !== null && _c !== void 0 ? _c : 0) + 1);
        if (((_d = failedLoginAttempts.get(userKey)) !== null && _d !== void 0 ? _d : 0) >= 3) {
            broadcastEvent({ type: 'alert', message: 'Multiple failed logins detected', email, ip: ip || 'unknown', country: geo.country || 'unknown' });
        }
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    failedLoginAttempts.delete(userKey);
    const accessToken = jsonwebtoken_1.default.sign({ userId: user._id.toString() }, 'this_is_a_secret_key', { expiresIn: '15m' });
    const refreshToken = jsonwebtoken_1.default.sign({ userId: user._id.toString() }, 'this_is_a_refresh_secret_key', { expiresIn: '7d' });
    yield RefreshToken.create({ userId: user._id, token: refreshToken, expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) });
    yield AuditLog.create({ userId: user._id, action: 'User logged in', ip, country: geo.country, device });
    generateThreatEvent(user._id.toString(), 'User logged in', ip, geo, email, device);
    loginHistory.set(userKey, { country: geo.country, timestamp: new Date(), device });
    res.cookie('accessToken', accessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: 'Login successful' });
})));
app.post('/api/simulate-token-reuse', authMiddleware, ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const refreshToken = req.cookies.refreshToken;
        const ip = getClientIp(req);
        const geo = geoip_lite_1.default.lookup(ip) || { country: 'unknown' };
        if (refreshToken) {
            const decoded = jsonwebtoken_1.default.verify(refreshToken, 'this_is_a_refresh_secret_key');
            const now = Math.floor(Date.now() / 1000);
            if (now > (decoded.iat + 15 * 60)) {
                yield AuditLog.create({ userId: req.userId, action: 'Threat Event', icon: '⚠️', text: 'Token reuse attempt detected', time: new Date().toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country: geo.country || 'unknown' });
                broadcastEvent({ type: 'threat', icon: '⚠️', text: 'Token reuse attempt detected', time: new Date().toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country: geo.country || 'unknown', userId: req.userId });
                res.status(401).json({ error: 'Token reuse detected' });
            }
            else {
                res.json({ message: 'Token still valid' });
            }
        }
        else {
            res.status(401).json({ error: 'No token provided' });
        }
    }
    catch (err) {
        res.status(500).json({ error: 'Simulation failed' });
    }
})));
app.post('/api/refresh', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken)
        return res.status(401).json({ error: 'No refresh token provided' });
    try {
        const decoded = jsonwebtoken_1.default.verify(refreshToken, 'this_is_a_refresh_secret_key');
        const tokenDoc = yield RefreshToken.findOne({ token: refreshToken, expires: { $gt: new Date() } });
        if (!tokenDoc)
            return res.status(401).json({ error: 'Invalid or expired refresh token' });
        const user = yield User.findById(decoded.userId);
        if (!user)
            return res.status(404).json({ error: 'User not found' });
        const newAccessToken = jsonwebtoken_1.default.sign({ userId: user._id.toString() }, 'this_is_a_secret_key', { expiresIn: '15m' });
        res.cookie('accessToken', newAccessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
        res.json({ message: 'Token refreshed' });
    }
    catch (err) {
        res.status(401).json({ error: 'Refresh failed' });
    }
})));
app.post('/api/logout', authMiddleware, ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            yield RefreshToken.deleteOne({ token: refreshToken });
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            yield AuditLog.create({ userId: req.userId, action: 'User logged out' });
            broadcastEvent({ type: 'log', action: 'User logged out', userId: req.userId });
        }
        else {
            res.json({ message: 'No active session to log out' });
        }
    }
    catch (err) {
        res.status(500).json({ error: 'Logout failed' });
    }
})));
app.post('/api/revoke-token', authMiddleware, ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            yield RefreshToken.deleteOne({ token: refreshToken });
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            yield AuditLog.create({ userId: req.userId, action: 'Token revoked' });
            broadcastEvent({ type: 'alert', message: 'Token revoked', userId: req.userId });
            res.json({ message: 'Token revoked successfully' });
        }
        else {
            res.json({ message: 'No token to revoke' });
        }
    }
    catch (err) {
        res.status(500).json({ error: 'Token revocation failed' });
    }
})));
app.get('/api/dashboard', authMiddleware, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const user = yield User.findById(req.userId);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ message: 'Welcome to your dashboard', email: user.email });
    }
    catch (err) {
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
}));
app.get('/api/threat-events', authMiddleware, ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const events = yield AuditLog.find({ userId: req.userId, action: 'Threat Event' })
            .sort({ timestamp: -1 })
            .limit(5);
        res.json(events);
    }
    catch (err) {
        res.status(500).json({ error: 'Failed to fetch threat events' });
    }
})));
app.get('/api/protected', authMiddleware, (req, res) => {
    res.json({ message: 'Protected data', userId: req.userId });
});
server.listen(5000, () => console.log('Server running on port 5000'));
