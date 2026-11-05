import mysql from "mysql2/promise";

const required = ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"] as const;
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
}

export const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  charset: "utf8mb4",
  timezone: "Z",
  decimalNumbers: false,
  enableKeepAlive: true
});

export async function dbReady() {
  const connection = await pool.getConnection();
  try {
    await connection.query("SELECT 1");
  } finally {
    connection.release();
  }
}
