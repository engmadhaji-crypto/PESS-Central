import { Router } from "express";
import { z } from "zod";
import argon2 from "argon2";
import { pool } from "./db.js";
import { issueSession, securityEvent } from "./security.js";
import type { RowDataPacket } from "mysql2";

export const authRouter = Router();
const loginSchema = z.object({
  username: z.string().trim().min(1).max(80),
  pin: z.string().regex(/^\d{4,8}$/)
});

authRouter.post("/login", async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
    const { username, pin } = parsed.data;
    const [lockRows] = await pool.execute<RowDataPacket[]>(
      "SELECT failed_attempts,locked_until FROM login_locks WHERE username=? LIMIT 1", [username]
    );
    const lock = lockRows[0];
    if (lock?.locked_until && new Date(lock.locked_until).getTime() > Date.now()) {
      await securityEvent(req, "pin_login_blocked", "medium", { username });
      return res.status(429).json({ error: "تم قفل الدخول مؤقتاً. حاول لاحقاً." });
    }
    const [rows] = await pool.execute<RowDataPacket[]>(
      "SELECT id,username,display_name,pin_hash,role,is_active FROM app_users WHERE username=? LIMIT 1", [username]
    );
    const user = rows[0];
    const ok = !!user && !!user.is_active && await argon2.verify(user.pin_hash, pin).catch(() => false);
    await pool.execute("INSERT INTO pin_attempts(username,succeeded,ip_address) VALUES(?,?,?)",
      [username, ok, null]);
    if (!ok) {
      const max = Number(process.env.PIN_MAX_ATTEMPTS || 5);
      const minutes = Number(process.env.PIN_LOCK_MINUTES || 15);
      await pool.execute(
        `INSERT INTO login_locks(username,failed_attempts,locked_until) VALUES(?,1,NULL)
         ON DUPLICATE KEY UPDATE failed_attempts=failed_attempts+1,
         locked_until=IF(failed_attempts+1>=?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? MINUTE),locked_until)`,
        [username, max, minutes]
      );
      await securityEvent(req, "pin_login_failed", "high", { username });
      return res.status(401).json({ error: "رمز الدخول غير صحيح" });
    }
    await pool.execute("DELETE FROM login_locks WHERE username=?", [username]);
    await securityEvent(req, "pin_login_success", "info", { username });
    const session = issueSession(Number(user.id));
    res.cookie("pess_session", session.token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production",
      sameSite: "strict", maxAge: 8 * 60 * 60 * 1000, path: "/"
    });
    return res.json({ user: { id: Number(user.id), username, displayName: user.display_name, role: user.role } });
  } catch (e) { next(e); }
});

authRouter.post("/logout", async (req, res, next) => {
  try {
    await securityEvent(req, "logout", "info");
    res.clearCookie("pess_session", { httpOnly: true, sameSite: "strict", path: "/" });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

authRouter.get("/me", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "غير مصرح" });
  res.json({ user: req.user });
});
