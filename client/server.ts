import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { rateLimit } from 'express-rate-limit';
import { Schema, model } from 'mongoose';
import crypto from 'crypto';

// Extend the Request interface to include userId
declare module 'express' {
  interface Request {
    userId?: string;
  }
}

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.',
  })
);

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/securevault').then(() => console.log('MongoDB connected'));

// User Schema
interface IUser extends mongoose.Document {
  email: string;
  password: string;
  consent: boolean;
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
}
const auditLogSchema = new Schema<IAuditLog>({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
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

// Authentication Middleware
const authMiddleware: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return; // Exit without returning a value
  }
  try {
    const decoded = jwt.verify(token, 'this_is_a_secret_key') as { userId: string };
    req.userId = decoded.userId;
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
    return; // Exit without returning a value
  }
};

// Routes
app.post('/api/register', (async (req: Request, res: Response) => {
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
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword, consent });
    await user.save();
    await AuditLog.create({ userId: user._id, action: 'User registered' });
    console.log(`Mock email sent to ${email}`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed' });
  }
}) as RequestHandler);

app.post('/api/reset-password', (async (req: Request, res: Response) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = crypto.randomUUID();
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await ResetToken.create({ userId: user._id, token, expires });
    console.log(`Mock reset email sent to ${email} with token: ${token}`);
    await AuditLog.create({ userId: user._id, action: 'Password reset requested' });
    res.json({ message: 'Password reset link sent' });
  } catch (err) {
    res.status(400).json({ error: 'Reset request failed' });
  }
}) as RequestHandler);

app.post('/api/reset-password/:token', (async (req: Request, res: Response) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const resetToken = await ResetToken.findOne({ token, expires: { $gt: new Date() } });
    if (!resetToken) return res.status(400).json({ error: 'Invalid or expired token' });
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.updateOne({ _id: resetToken.userId }, { password: hashedPassword });
    await ResetToken.deleteOne({ token });
    await AuditLog.create({ userId: resetToken.userId, action: 'Password reset completed' });
    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Password reset failed' });
  }
}) as RequestHandler);

// Sample protected route to use authMiddleware
app.get('/api/protected', authMiddleware, (req: Request, res: Response) => {
  res.json({ message: 'Protected data', userId: req.userId });
});

app.listen(5000, () => console.log('Server running on port 5000'));
