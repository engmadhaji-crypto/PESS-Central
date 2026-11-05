import { Router } from "express";
import { z } from "zod";
import { pool } from "./db.js";
import { requireAuth, securityEvent } from "./security.js";
import type { RowDataPacket, ResultSetHeader } from "mysql2";

export const apiRouter = Router();
apiRouter.use(requireAuth);

const customerInput = z.object({
  name: z.string().trim().min(1).max(200),
  phone: z.string().trim().max(40).optional().nullable(),
  address: z.string().max(10000).optional().nullable(),
  notes: z.string().max(20000).optional().nullable(),
  extra: z.record(z.unknown()).optional()
});
const contractInput = z.object({
  customerId: z.number().int().positive(),
  contractNumber: z.string().max(100).optional().nullable(),
  title: z.string().trim().min(1).max(220),
  description: z.string().max(20000).optional().nullable(),
  totalAmount: z.string().regex(/^\d{1,13}(\.\d{1,2})?$/),
  costAmount: z.string().regex(/^\d{1,13}(\.\d{1,2})?$/).default("0"),
  startDate: z.string().date().optional().nullable(),
  endDate: z.string().date().optional().nullable()
});
const paymentInput = z.object({
  customerId: z.number().int().positive(),
  contractId: z.number().int().positive().optional().nullable(),
  paymentDate: z.string().date(),
  amount: z.string().regex(/^\d{1,13}(\.\d{1,2})?$/),
  method: z.string().max(80).optional().nullable(),
  referenceNo: z.string().max(120).optional().nullable(),
  notes: z.string().max(20000).optional().nullable()
});

apiRouter.get("/customers", async (req, res, next) => {
  try {
    const q = String(req.query.q || "").trim().slice(0,100);
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,legacy_id,name,phone,address,notes,status,created_at,updated_at
       FROM customers WHERE status='active' AND (?='' OR name LIKE CONCAT('%',?,'%') OR phone LIKE CONCAT('%',?,'%'))
       ORDER BY name LIMIT 500`, [q,q,q]);
    res.json({ data: rows });
  } catch (e) { next(e); }
});

apiRouter.post("/customers", async (req, res, next) => {
  try {
    const p = customerInput.safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: "بيانات العميل غير مكتملة", details: p.error.flatten() });
    const [r] = await pool.execute<ResultSetHeader>(
      `INSERT INTO customers(name,phone,address,notes,extra,created_by) VALUES(?,?,?,?,?,?)`,
      [p.data.name,p.data.phone ?? null,p.data.address ?? null,p.data.notes ?? null,
       JSON.stringify(p.data.extra ?? {}),req.user!.id]);
    await securityEvent(req, "customer_created", "info", { customerId: r.insertId });
    res.status(201).json({ id: r.insertId });
  } catch (e) { next(e); }
});

apiRouter.patch("/customers/:id", async (req, res, next) => {
  try {
    const id = Number(req.params.id), p = customerInput.partial().safeParse(req.body);
    if (!Number.isSafeInteger(id) || id < 1 || !p.success) return res.status(400).json({ error: "بيانات غير صالحة" });
    const [beforeRows] = await pool.execute<RowDataPacket[]>("SELECT * FROM customers WHERE id=? AND status='active'", [id]);
    if (!beforeRows[0]) return res.status(404).json({ error: "العميل غير موجود" });
    const before = beforeRows[0];
    const d = p.data;
    await pool.execute(
      `UPDATE customers SET name=COALESCE(?,name),phone=?,address=?,notes=?,extra=COALESCE(?,extra) WHERE id=?`,
      [d.name ?? null, d.phone ?? before.phone, d.address ?? before.address, d.notes ?? before.notes,
       d.extra ? JSON.stringify(d.extra) : null, id]);
    const [afterRows] = await pool.execute<RowDataPacket[]>("SELECT * FROM customers WHERE id=?", [id]);
    await pool.execute(
      `INSERT INTO audit_logs(entity_type,entity_id,action,actor_user_id,before_data,after_data,request_id)
       VALUES('customer',?,'update',?,?,?,?)`,
      [id,req.user!.id,JSON.stringify(before),JSON.stringify(afterRows[0]),req.requestId ?? null]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

apiRouter.post("/customers/:id/archive", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const [contracts] = await pool.execute<RowDataPacket[]>(
      "SELECT COUNT(*) AS n FROM contracts WHERE customer_id=? AND status<>'archived'", [id]);
    if (Number(contracts[0]?.n || 0) > 0) return res.status(409).json({ error: "لا يمكن أرشفة عميل لديه عقود نشطة" });
    await pool.execute("UPDATE customers SET status='archived',archived_at=UTC_TIMESTAMP(3) WHERE id=?", [id]);
    await securityEvent(req, "customer_archived", "medium", { customerId: id });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

apiRouter.get("/contracts", async (_req, res, next) => {
  try {
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT c.*, cu.name AS customer_name FROM contracts c
       JOIN customers cu ON cu.id=c.customer_id WHERE c.status<>'archived'
       ORDER BY c.created_at DESC LIMIT 1000`);
    res.json({ data: rows });
  } catch (e) { next(e); }
});

apiRouter.post("/contracts", async (req, res, next) => {
  try {
    const p = contractInput.safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: "بيانات العقد غير صالحة", details: p.error.flatten() });
    const d = p.data;
    const [r] = await pool.execute<ResultSetHeader>(
      `INSERT INTO contracts(customer_id,contract_number,title,description,total_amount,cost_amount,start_date,end_date,created_by)
       VALUES(?,?,?,?,?,?,?,?,?)`,
      [d.customerId,d.contractNumber ?? null,d.title,d.description ?? null,d.totalAmount,d.costAmount,
       d.startDate ?? null,d.endDate ?? null,req.user!.id]);
    await securityEvent(req, "contract_created", "info", { contractId: r.insertId });
    res.status(201).json({ id: r.insertId });
  } catch (e) { next(e); }
});

apiRouter.post("/contracts/:id/archive", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const [r] = await pool.execute<ResultSetHeader>(
      "UPDATE contracts SET status='archived',archived_at=UTC_TIMESTAMP(3) WHERE id=? AND status<>'archived'", [id]);
    if (!r.affectedRows) return res.status(404).json({ error: "العقد غير موجود" });
    await securityEvent(req, "contract_archived", "medium", { contractId: id });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

apiRouter.get("/payments", async (req, res, next) => {
  try {
    const customerId = req.query.customerId ? Number(req.query.customerId) : null;
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT p.*,c.name AS customer_name,ct.title AS contract_title FROM payments p
       JOIN customers c ON c.id=p.customer_id LEFT JOIN contracts ct ON ct.id=p.contract_id
       WHERE p.status='posted' AND (? IS NULL OR p.customer_id=?)
       ORDER BY p.payment_date ASC,p.id ASC LIMIT 2000`, [customerId,customerId]);
    res.json({ data: rows });
  } catch (e) { next(e); }
});

apiRouter.post("/payments", async (req, res, next) => {
  const conn = await pool.getConnection();
  try {
    const p = paymentInput.safeParse(req.body);
    if (!p.success) { conn.release(); return res.status(400).json({ error: "بيانات الدفعة غير صالحة", details: p.error.flatten() }); }
    const d = p.data;
    await conn.beginTransaction();
    const [r] = await conn.execute<ResultSetHeader>(
      `INSERT INTO payments(customer_id,contract_id,payment_date,amount,method,reference_no,notes,created_by)
       VALUES(?,?,?,?,?,?,?,?)`,
      [d.customerId,d.contractId ?? null,d.paymentDate,d.amount,d.method ?? null,d.referenceNo ?? null,d.notes ?? null,req.user!.id]);
    await conn.commit();
    await securityEvent(req, "payment_recorded", "info", { paymentId: r.insertId });
    res.status(201).json({ id: r.insertId });
  } catch (e) {
    await conn.rollback().catch(() => {});
    next(e);
  } finally { conn.release(); }
});

apiRouter.post("/payments/:id/void", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const [r] = await pool.execute<ResultSetHeader>(
      "UPDATE payments SET status='voided',voided_at=UTC_TIMESTAMP(3) WHERE id=? AND status='posted'", [id]);
    if (!r.affectedRows) return res.status(404).json({ error: "الدفعة غير موجودة أو ملغاة" });
    await securityEvent(req, "payment_voided", "high", { paymentId: id });
    res.json({ ok: true, note: "تم إلغاء الدفعة دون حذفها نهائياً" });
  } catch (e) { next(e); }
});

apiRouter.get("/statements/customer/:id", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const [customer] = await pool.execute<RowDataPacket[]>(
      "SELECT id,name,phone FROM customers WHERE id=? AND status='active'", [id]);
    if (!customer[0]) return res.status(404).json({ error: "العميل غير موجود" });
    const [contracts] = await pool.execute<RowDataPacket[]>(
      `SELECT c.id,c.title,c.contract_number,c.total_amount,c.cost_amount,c.status,
       COALESCE(SUM(CASE WHEN p.status='posted' THEN p.amount ELSE 0 END),0) AS paid
       FROM contracts c LEFT JOIN payments p ON p.contract_id=c.id
       WHERE c.customer_id=? GROUP BY c.id ORDER BY c.created_at`, [id]);
    const [payments] = await pool.execute<RowDataPacket[]>(
      `SELECT id,payment_date,amount,method,reference_no,contract_id,notes
       FROM payments WHERE customer_id=? AND status='posted'
       ORDER BY payment_date ASC,id ASC`, [id]);
    res.json({ customer: customer[0], contracts, payments });
  } catch (e) { next(e); }
});

apiRouter.get("/reports/summary", async (_req, res, next) => {
  try {
    const [rows] = await pool.query<RowDataPacket[]>(`
      SELECT
       (SELECT COUNT(*) FROM customers WHERE status='active') AS customers,
       (SELECT COUNT(*) FROM contracts WHERE status NOT IN ('archived','cancelled')) AS contracts,
       (SELECT COALESCE(SUM(total_amount),0) FROM contracts WHERE status NOT IN ('archived','cancelled')) AS contract_value,
       (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='posted') AS collected
    `);
    res.json(rows[0]);
  } catch (e) { next(e); }
});
