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
const mongoose_2 = require("mongoose");
const crypto_1 = __importDefault(require("crypto"));
const app = (0, express_1.default)();
// Middleware
app.use((0, cors_1.default)());
app.use(express_1.default.json());
app.use((0, express_rate_limit_1.rateLimit)({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.',
}));
// MongoDB connection
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
});
const AuditLog = (0, mongoose_2.model)('AuditLog', auditLogSchema);
const resetTokenSchema = new mongoose_2.Schema({
    userId: { type: mongoose_2.Schema.Types.ObjectId, ref: 'User' },
    token: { type: String, required: true },
    expires: { type: Date, required: true },
});
const ResetToken = (0, mongoose_2.model)('ResetToken', resetTokenSchema);
// Authentication Middleware
const authMiddleware = (req, res, next) => {
    var _a;
    const token = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
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
// Routes
app.post('/api/register', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password, consent } = req.body;
    if (!email || !password || consent === undefined) {
        return res.status(400).json({ error: 'Email, password and consent are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    if (!consent) {
        return res.status(400).json({ error: 'Consent required for data processing' });
    }
    try {
        const hashedPassword = yield bcryptjs_1.default.hash(password, 12);
        const user = new User({ email, password: hashedPassword, consent });
        yield user.save();
        yield AuditLog.create({ userId: user._id, action: 'User registered' });
        console.log(`Mock email sent to ${email}`);
        res.status(201).json({ message: 'User registered successfully' });
    }
    catch (err) {
        res.status(400).json({ error: 'Registration failed' });
    }
})));
app.post('/api/reset-password', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email } = req.body;
    try {
        const user = yield User.findOne({ email });
        if (!user)
            return res.status(404).json({ error: 'User not found' });
        const token = crypto_1.default.randomUUID();
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        yield ResetToken.create({ userId: user._id, token, expires });
        console.log(`Mock reset email sent to ${email} with token: ${token}`);
        yield AuditLog.create({ userId: user._id, action: 'Password reset requested' });
        res.json({ message: 'Password reset link sent' });
    }
    catch (err) {
        res.status(400).json({ error: 'Reset request failed' });
    }
})));
app.post('/api/reset-password/:token', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const resetToken = yield ResetToken.findOne({ token, expires: { $gt: new Date() } });
        if (!resetToken)
            return res.status(400).json({ error: 'Invalid or expired token' });
        const hashedPassword = yield bcryptjs_1.default.hash(password, 12);
        yield User.updateOne({ _id: resetToken.userId }, { password: hashedPassword });
        yield ResetToken.deleteOne({ token });
        yield AuditLog.create({ userId: resetToken.userId, action: 'Password reset completed' });
        res.json({ message: 'Password reset successfully' });
    }
    catch (err) {
        res.status(400).json({ error: 'Password reset failed' });
    }
})));
// New Login Route
app.post('/api/login', ((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    try {
        const user = yield User.findOne({ email });
        if (!user || !(yield bcryptjs_1.default.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const token = jsonwebtoken_1.default.sign({ userId: user._id.toString() }, 'this_is_a_secret_key', { expiresIn: '1h' });
        yield AuditLog.create({ userId: user._id, action: 'User logged in' });
        res.json({ token });
    }
    catch (err) {
        res.status(500).json({ error: 'Login failed due to server error' });
    }
})));
// Sample protected route to use authMiddleware
app.get('/api/protected', authMiddleware, (req, res) => {
    res.json({ message: 'Protected data', userId: req.userId });
});
app.listen(5000, () => console.log('Server running on port 5000'));
