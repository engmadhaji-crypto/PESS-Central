import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { dbReady } from "./db.js";
import { authRouter } from "./auth.js";
import { apiRouter } from "./crud.js";
import { alertsRouter } from "./alerts.js";
import { requestContext, requireAuth } from "./security.js";

const app = express();
app.set("trust proxy", 1);
app.use(requestContext);
app.use(helmet({ crossOriginResourcePolicy: { policy: "same-site" } }));
app.use(cors({ origin: process.env.APP_ORIGIN?.split(",") ?? false, credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.get("/api/health", async (_req,res) => {
  try { await dbReady(); res.json({ ok: true, database: "connected" }); }
  catch { res.status(503).json({ ok: false, database: "unavailable" }); }
});

app.use("/api/auth", rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }), authRouter);
app.use("/api", apiRouter);
app.use("/api/alerts", alertsRouter);
app.get("/api/security/events", requireAuth, async (_req,res) => {
  // Read-only event stream. No mutation endpoint is exposed.
  const { pool } = await import("./db.js");
  const [rows] = await pool.query("SELECT id,event_type,severity,actor_user_id,request_id,metadata,created_at FROM securityevents ORDER BY created_at DESC LIMIT 300");
  res.json({ data: rows });
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("PESS API error", err);
  res.status(500).json({ error: "حدث خطأ داخلي. راجع سجل الخادم باستخدام رقم الطلب." });
});

const port = Number(process.env.PORT || 3000);
dbReady().then(() => {
  app.listen(port, "0.0.0.0", () => console.log(`PESS API listening on ${port}`));
}).catch((err) => {
  console.error("Database connection failed; server not started.", err);
  process.exit(1);
});
