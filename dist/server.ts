import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import jwt from 'jsonwebtoken';
const swaggerParser = require('swagger-parser'); // Use require for swagger-parser
import { rateLimit } from 'express-rate-limit';
import { Server } from 'http';
import { Server as WebSocketServer } from 'ws';
import { Schema, model } from 'mongoose';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import geoip from 'geoip-lite';
import multer, { Multer } from 'multer';
import jsyaml from 'js-yaml';

declare module 'express' {
  interface Request {
    userId?: string;
    file?: Express.Multer.File;
  }
}

const app = express();
const server = new Server(app);
const wss = new WebSocketServer({ server });

const getClientIp = (req: Request): string => {
  return req.headers['x-forwarded-for']?.toString().split(',')[0] || req.ip || 'unknown';
};

// Multer setup for file uploads (corrected storage method)
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.',
  })
);

mongoose.connect('mongodb://localhost:27017/securevault').then(() => console.log('MongoDB connected'));

interface IUser extends mongoose.Document {
  email: string;
  password: string;
  consent: boolean;
  _id: mongoose.Types.ObjectId;
}
const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  consent: { type: Boolean, default: true },
});
const User = model<IUser>('User', userSchema);

interface IAuditLog extends mongoose.Document {
  userId: mongoose.Types.ObjectId;
  action: string;
  timestamp: Date;
  ip?: string;
  country?: string;
  device?: string;
  icon?: string;
  text?: string;
  color?: string;
}
const auditLogSchema = new Schema<IAuditLog>({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  ip: { type: String },
  country: { type: String },
  device: { type: String },
  icon: { type: String },
  text: { type: String },
  color: { type: String },
});
const AuditLog = model<IAuditLog>('AuditLog', auditLogSchema);

interface IResetToken extends mongoose.Document {
  userId: mongoose.Types.ObjectId;
  token: string;
  expires: Date;
}
const resetTokenSchema = new Schema<IResetToken>({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  token: { type: String, required: true },
  expires: { type: Date, required: true },
});
const ResetToken = model<IResetToken>('ResetToken', resetTokenSchema);

interface IRefreshToken extends mongoose.Document {
  userId: mongoose.Types.ObjectId;
  token: string;
  expires: Date;
}
const refreshTokenSchema = new Schema<IRefreshToken>({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  token: { type: String, required: true },
  expires: { type: Date, required: true },
});
const RefreshToken = model<IRefreshToken>('RefreshToken', refreshTokenSchema);

// Note Schema
interface INote extends mongoose.Document {
  title: string;
  content: string;
  encryptedContent: string;
  iv: string;
  createdBy: mongoose.Types.ObjectId;
  expiresAt: Date;
  token: string;
  used: boolean;
}
const noteSchema = new Schema<INote>({
  title: { type: String, required: true },
  content: { type: String, required: true },
  encryptedContent: { type: String, required: true },
  iv: { type: String, required: true },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
  token: { type: String, required: true, unique: true },
  used: { type: Boolean, default: false },
});
const Note = model<INote>('Note', noteSchema);

// Encryption functions
const encrypt = (text: string, secret: string): { encrypted: string; iv: string } => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secret), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
};

const decrypt = (encrypted: string, iv: string, secret: string): string => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secret), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const authMiddleware: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.accessToken;
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }
  try {
    const decoded = jwt.verify(token, 'this_is_a_secret_key') as { userId: string };
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }
};

const failedLoginAttempts = new Map<string, number>();
const loginHistory = new Map<string, { country: string; timestamp: Date; device?: string }>();
const deviceHistory = new Map<string, string>();

setInterval(() => {
  const now = Date.now();
  for (const [key] of failedLoginAttempts) {
    const loginData = loginHistory.get(key);
    if (loginData && now - (loginData.timestamp?.getTime() ?? 0) > 24 * 60 * 60 * 1000) {
      failedLoginAttempts.delete(key);
    }
  }
  for (const [key] of loginHistory) {
    const loginData = loginHistory.get(key);
    if (loginData && now - (loginData.timestamp?.getTime() ?? 0) > 24 * 60 * 60 * 1000) {
      loginHistory.delete(key);
    }
  }
}, 24 * 60 * 60 * 1000);

wss.on('connection', (ws) => {
  ws.on('message', (message) => console.log('Received:', message));
  ws.on('close', () => console.log('Client disconnected'));
});

const broadcastEvent = (event: any) => {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) client.send(JSON.stringify(event));
  });
};

const generateThreatEvent = (userId: string, action: string, ip: string, geo: any, email: string, device: string) => {
  const events = [];
  const userKey = `${ip}-${email}`;
  const now = new Date();
  const hour = now.getHours();
  const country = geo?.country || 'unknown';

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
  const attemptCount = failedLoginAttempts.get(userKey) ?? 0;
  if (attemptCount >= 3) {
    events.push({ icon: '⚠️', text: `Multiple failed logins from ${ip}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
  }
  const prevLogin = loginHistory.get(userKey);
  if (prevLogin && prevLogin.country !== country) {
    events.push({ icon: '⚠️', text: `Geo-switch from ${prevLogin.country} to ${country}`, time: now.toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country });
  }
  events.forEach((event) => {
    AuditLog.create({ userId, action: 'Threat Event', ...event });
    broadcastEvent({ type: 'threat', ...event, userId });
  });
};

app.post('/api/register', (async (req: Request, res: Response) => {
  const { email, password, consent } = req.body;
  if (!email || !password || consent === undefined) return res.status(400).json({ error: 'Email, password and consent are required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (!consent) return res.status(400).json({ error: 'Consent required for data processing' });
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword, consent });
    await user.save();
    const ip = getClientIp(req);
    const geo = geoip.lookup(ip) || { country: 'unknown' };
    await AuditLog.create({ userId: user._id, action: 'User registered', ip, country: geo.country });
    broadcastEvent({ type: 'log', action: 'User registered', email, country: geo.country });
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed' });
  }
}) as RequestHandler);

app.post('/api/login', (async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const ip = getClientIp(req);
  const geo = geoip.lookup(ip) || { country: 'unknown' };
  const userKey = `${ip}-${email}`;
  const device = req.get('User-Agent') || 'unknown';
  const user = await User.findOne({ email });
  if (!user) {
    failedLoginAttempts.set(userKey, (failedLoginAttempts.get(userKey) ?? 0) + 1);
    if ((failedLoginAttempts.get(userKey) ?? 0) >= 3) {
      broadcastEvent({ type: 'alert', message: 'Multiple failed logins detected', email, ip: ip || 'unknown', country: geo.country || 'unknown' });
    }
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  if (!(await bcrypt.compare(password, user.password))) {
    failedLoginAttempts.set(userKey, (failedLoginAttempts.get(userKey) ?? 0) + 1);
    if ((failedLoginAttempts.get(userKey) ?? 0) >= 3) {
      broadcastEvent({ type: 'alert', message: 'Multiple failed logins detected', email, ip: ip || 'unknown', country: geo.country || 'unknown' });
    }
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  failedLoginAttempts.delete(userKey);
  const accessToken = jwt.sign({ userId: user._id.toString() }, 'this_is_a_secret_key', { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user._id.toString() }, 'this_is_a_refresh_secret_key', { expiresIn: '7d' });
  await RefreshToken.create({ userId: user._id, token: refreshToken, expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) });
  await AuditLog.create({ userId: user._id, action: 'User logged in', ip, country: geo.country, device });
  generateThreatEvent(user._id.toString(), 'User logged in', ip, geo, email, device);
  loginHistory.set(userKey, { country: geo.country, timestamp: new Date(), device });
  res.cookie('accessToken', accessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ message: 'Login successful' });
}) as RequestHandler);

app.post('/api/simulate-token-reuse', authMiddleware, (async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    const ip = getClientIp(req);
    const geo = geoip.lookup(ip) || { country: 'unknown' };
    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, 'this_is_a_refresh_secret_key') as { userId: string; iat: number };
      const now = Math.floor(Date.now() / 1000);
      if (now > (decoded.iat + 15 * 60)) {
        await AuditLog.create({ userId: req.userId, action: 'Threat Event', icon: '⚠️', text: 'Token reuse attempt detected', time: new Date().toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country: geo.country || 'unknown' });
        broadcastEvent({ type: 'threat', icon: '⚠️', text: 'Token reuse attempt detected', time: new Date().toLocaleTimeString(), color: 'red', ip: ip || 'unknown', country: geo.country || 'unknown', userId: req.userId });
        res.status(401).json({ error: 'Token reuse detected' });
      } else {
        res.json({ message: 'Token still valid' });
      }
    } else {
      res.status(401).json({ error: 'No token provided' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Simulation failed' });
  }
}));

app.post('/api/refresh', (async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });
  try {
    const decoded = jwt.verify(refreshToken, 'this_is_a_refresh_secret_key') as { userId: string };
    const tokenDoc = await RefreshToken.findOne({ token: refreshToken, expires: { $gt: new Date() } });
    if (!tokenDoc) return res.status(401).json({ error: 'Invalid or expired refresh token' });
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const newAccessToken = jwt.sign({ userId: user._id.toString() }, 'this_is_a_secret_key', { expiresIn: '15m' });
    res.cookie('accessToken', newAccessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.json({ message: 'Token refreshed' });
  } catch (err) {
    res.status(401).json({ error: 'Refresh failed' });
  }
}) as RequestHandler);

app.post('/api/logout', authMiddleware, (async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      await AuditLog.create({ userId: req.userId, action: 'User logged out' });
      broadcastEvent({ type: 'log', action: 'User logged out', userId: req.userId });
    } else {
      res.json({ message: 'No active session to log out' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
}));

app.post('/api/revoke-token', authMiddleware, (async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      await AuditLog.create({ userId: req.userId, action: 'Token revoked' });
      broadcastEvent({ type: 'alert', message: 'Token revoked', userId: req.userId });
      res.json({ message: 'Token revoked successfully' });
    } else {
      res.json({ message: 'No token to revoke' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Token revocation failed' });
  }
}));

app.get('/api/dashboard', authMiddleware, async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.json({ message: 'Welcome to your dashboard', email: user.email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

app.get('/api/threat-events', authMiddleware, (async (req: Request, res: Response) => {
  try {
    const events = await AuditLog.find({ userId: req.userId, action: 'Threat Event' })
      .sort({ timestamp: -1 })
      .limit(5);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch threat events' });
  }
}));

app.post('/api/scan-api', authMiddleware, upload.single('file'), (async (req: Request, res: Response) => {
  if (!req.file) {
    res.status(400).json({ error: 'No file uploaded' });
    return;
  }

  const file = req.file;
  let apiDoc: any;
  try {
    if (file.originalname.endsWith('.yaml')) {
      apiDoc = jsyaml.load(file.buffer.toString());
    } else if (file.originalname.endsWith('.json')) {
      apiDoc = JSON.parse(file.buffer.toString());
    } else {
      res.status(400).json({ error: 'Unsupported file type' });
      return;
    }

    await swaggerParser.validate(apiDoc);
    res.json({ message: 'File parsed successfully', api: apiDoc });
  } catch (err) {
    res.status(400).json({ error: 'Invalid OpenAPI/Swagger file', details: (err as Error).message });
  }
}) as RequestHandler);

app.post('/api/create-note', authMiddleware, (async (req: Request, res: Response) => {
  const { title, content, expiresInHours = 24 } = req.body;
  if (!title || !content) {
    res.status(400).json({ error: 'Title and content are required' });
    return;
  }

  const secret = crypto.randomBytes(32).toString('hex');
  const { encrypted, iv } = encrypt(content, secret);
  const token = jwt.sign({ secret }, 'note_secret_key', { expiresIn: `${expiresInHours}h` });

  const note = new Note({
    title,
    content,
    encryptedContent: encrypted,
    iv,
    createdBy: req.userId,
    expiresAt: new Date(Date.now() + expiresInHours * 60 * 60 * 1000),
    token,
    used: false,
  });

  await note.save();
  res.json({ message: 'Note created successfully', link: `http://localhost:5173/api/retrieve-note/${token}` });
}) as RequestHandler);

app.get('/api/retrieve-note/:token', (async (req: Request, res: Response) => {
  const { token } = req.params;
  try {
    const decoded = jwt.verify(token, 'note_secret_key') as { secret: string };
    const note = await Note.findOne({ token, expiresAt: { $gt: new Date() }, used: false });
    if (!note) {
      res.status(404).json({ error: 'Note not found or expired' });
      return;
    }

    const content = decrypt(note.encryptedContent, note.iv, decoded.secret);
    note.used = true;
    await note.save();
    res.json({ title: note.title, content, expiresAt: note.expiresAt });
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
}) as RequestHandler);

app.get('/api/protected', authMiddleware, (req: Request, res: Response) => {
  res.json({ message: 'Protected data', userId: req.userId });
});

server.listen(5000, () => console.log('Server running on port 5000'));