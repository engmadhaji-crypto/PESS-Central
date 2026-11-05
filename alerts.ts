import { Router } from "express";
import crypto from "node:crypto";
import { pool } from "./db.js";
import { requireAuth, requireRole } from "./security.js";
import type { RowDataPacket, ResultSetHeader } from "mysql2";

export const alertsRouter = Router();
alertsRouter.use(requireAuth);

alertsRouter.get("/", requireRole("owner","admin"), async (_req,res,next) => {
  try {
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT a.*,r.name AS rule_name FROM alerts a LEFT JOIN alert_rules r ON r.id=a.rule_id
       ORDER BY a.created_at DESC LIMIT 500`);
    res.json({ data: rows });
  } catch(e) { next(e); }
});

alertsRouter.post("/rules", requireRole("owner","admin"), async (req,res,next) => {
  try {
    const { name,eventType,minSeverity="medium",webhookEnabled=false } = req.body ?? {};
    if (typeof name !== "string" || !name.trim() || typeof eventType !== "string" || !eventType.trim())
      return res.status(400).json({ error: "اسم القاعدة ونوع الحدث مطلوبان" });
    const [r] = await pool.execute<ResultSetHeader>(
      "INSERT INTO alert_rules(name,event_type,min_severity,webhook_enabled) VALUES(?,?,?,?)",
      [name.trim().slice(0,160),eventType.trim().slice(0,100),minSeverity,!!webhookEnabled]);
    res.status(201).json({ id: r.insertId });
  } catch(e) { next(e); }
});

export async function deliverSecurityWebhook(alertId: number, eventType: string, severity: string) {
  const url = process.env.SECURITY_WEBHOOK_URL, secret = process.env.SECURITY_WEBHOOK_SECRET;
  if (!url || !secret) return;
  const body = JSON.stringify({ alertId, eventType, severity, timestamp: new Date().toISOString() });
  const signature = crypto.createHmac("sha256", secret).update(body).digest("hex");
  let outcome: "sent"|"failed" = "failed", status: number|null = null, excerpt: string|null = null;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-pess-signature": `sha256=${signature}` },
      body, signal: AbortSignal.timeout(8000)
    });
    status = response.status;
    outcome = response.ok ? "sent" : "failed";
    excerpt = (await response.text()).slice(0,500);
  } catch (e) { excerpt = String(e).slice(0,500); }
  await pool.execute(
    "INSERT INTO alert_delivery_attempts(alert_id,channel,outcome,http_status,response_excerpt) VALUES(?,'webhook',?,?,?)",
    [alertId,outcome,status,excerpt]);
}
