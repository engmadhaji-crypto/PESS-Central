import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { pool } from "./db.js";
import type { RowDataPacket } from "mysql2";

export type AuthUser = { id: number; username: string; displayName: string; role: string };
declare global {
  namespace Express { interface Request { user?: AuthUser; requestId?: string } }
}

export function requestContext(req: Request, res: Response, next: NextFunction) {
  req.requestId = crypto.randomUUID();
  res.setHeader("X-Request-ID", req.requestId);
  next();
}

export async function securityEvent(
  req: Request, eventType: string, severity: "info"|"low"|"medium"|"high"|"critical",
  metadata: Record<string, unknown> = {}
) {
  const ip = req.ip;
  const packedIp = ip ? ipToBuffer(ip) : null;
  await pool.execute(
    `INSERT INTO securityevents (event_type,severity,actor_user_id,ip_address,user_agent,request_id,metadata)
     VALUES (?,?,?,?,?,?,?)`,
    [eventType, severity, req.user?.id ?? null, packedIp, req.get("user-agent")?.slice(0,500) ?? null,
     req.requestId ?? null, JSON.stringify(metadata)]
  );
}
function ipToBuffer(ip: string) {
  const normalized = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (normalized.includes(".")) return Buffer.from(normalized.split(".").map(Number));
  const clean = normalized.replace(/^::ffff:/, "");
  const parts = clean.split(":");
  const out = Buffer.alloc(16);
  let offset = 0;
  for (const p of parts) {
    if (!p) continue;
    const n = parseInt(p || "0", 16);
    if (offset < 16) { out.writeUInt16BE(n, offset); offset += 2; }
  }
  return out;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies?.pess_session;
  if (!token || !process.env.SESSION_SECRET) return res.status(401).json({ error: "غير مصرح" });
  try {
    const [id, expires, sig] = token.split(".");
    const expected = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(`${id}.${expires}`).digest("hex");
    if (!id || !expires || !sig || Number(expires) < Date.now() ||
        !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return res.status(401).json({ error: "انتهت الجلسة أو أنها غير صالحة" });
    }
    const [rows] = await pool.execute<RowDataPacket[]>(
      "SELECT id,username,display_name,role,is_active FROM app_users WHERE id=? LIMIT 1", [id]
    );
    const user = rows[0];
    if (!user || !user.is_active) return res.status(401).json({ error: "الحساب غير نشط" });
    req.user = { id: Number(user.id), username: user.username, displayName: user.display_name, role: user.role };
    next();
  } catch { return res.status(401).json({ error: "جلسة غير صالحة" }); }
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "ليست لديك الصلاحية" });
    next();
  };
}

export function issueSession(userId: number) {
  const expires = Date.now() + 8 * 60 * 60 * 1000;
  const body = `${userId}.${expires}`;
  const sig = crypto.createHmac("sha256", process.env.SESSION_SECRET!).update(body).digest("hex");
  return { token: `${body}.${sig}`, expires };
}
