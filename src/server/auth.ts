/**
 * Authentication & Authorization
 *
 * JWT-based auth with role-based access control.
 * Roles: ADMIN, ANALYST, APPROVER, READONLY
 */

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Request, Response, NextFunction } from 'express';
import { usersRepo, tenantsRepo } from '../database/repositories.js';

// ============================================================================
// Config
// ============================================================================

const JWT_SECRET = process.env['JWT_SECRET'] ?? 'watcher-mk1-dev-secret-change-in-production';
const JWT_EXPIRES_IN = process.env['JWT_EXPIRES_IN'] ?? '24h';

export interface JwtPayload {
  user_id: string;
  tenant_id: string;
  email: string;
  role: string;
}

// ============================================================================
// Token Operations
// ============================================================================

export function generateToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyToken(token: string): JwtPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as JwtPayload;
  } catch {
    return null;
  }
}

// ============================================================================
// Password Operations
// ============================================================================

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ============================================================================
// Express Middleware
// ============================================================================

/** Extends Express Request with authenticated user info */
declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

/**
 * Authentication middleware.
 * Extracts and verifies JWT from Authorization header.
 * If AUTH_ENABLED=false (default for dev), skips auth and uses a default user.
 */
export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Skip auth in development if not explicitly enabled
  if (process.env['AUTH_ENABLED'] !== 'true') {
    req.user = {
      user_id: 'dev-user',
      tenant_id: process.env['DEFAULT_TENANT_ID'] ?? 'tenant-001',
      email: 'dev@watcher.local',
      role: 'ADMIN',
    };
    next();
    return;
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token);

  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  req.user = payload;
  next();
}

/**
 * Role-based access control middleware.
 * Restricts access to specific roles.
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: `Access denied. Required role: ${roles.join(' or ')}` });
      return;
    }

    next();
  };
}

// ============================================================================
// Auth Routes (login, register)
// ============================================================================

import { Router } from 'express';

const authRouter = Router();

function generateId(): string {
  return `usr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * POST /api/v1/auth/register
 * Creates a new user + tenant (for first-time setup).
 */
authRouter.post('/register', async (req: Request, res: Response) => {
  const { email, password, name, tenant_name } = req.body as {
    email?: string; password?: string; name?: string; tenant_name?: string;
  };

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  // Check if user already exists
  const existing = await usersRepo.getByEmail(email);
  if (existing) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }

  const tenantId = `tenant-${Date.now()}`;
  const userId = generateId();
  const passwordHash = await hashPassword(password);

  // Create tenant
  await tenantsRepo.create(tenantId, tenant_name ?? `${email}'s Organization`);

  // Create user as ADMIN (first user of a tenant is always admin)
  await usersRepo.create({
    id: userId,
    tenant_id: tenantId,
    email,
    password_hash: passwordHash,
    role: 'ADMIN',
    name,
  });

  const token = generateToken({
    user_id: userId,
    tenant_id: tenantId,
    email,
    role: 'ADMIN',
  });

  return res.status(201).json({
    token,
    user: { id: userId, email, role: 'ADMIN', tenant_id: tenantId, name },
  });
});

/**
 * POST /api/v1/auth/login
 * Authenticates a user and returns a JWT.
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = await usersRepo.getByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const valid = await comparePassword(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  await usersRepo.updateLastLogin(user.id);

  const token = generateToken({
    user_id: user.id,
    tenant_id: user.tenant_id,
    email: user.email,
    role: user.role,
  });

  return res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role, tenant_id: user.tenant_id, name: user.name },
  });
});

/**
 * GET /api/v1/auth/me
 * Returns the current authenticated user.
 */
authRouter.get('/me', authMiddleware, (req: Request, res: Response) => {
  res.json({ user: req.user });
});

export { authRouter };
