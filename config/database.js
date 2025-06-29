const mysql = require("mysql2/promise");
require("dotenv").config();

let pool;

try {
  pool = mysql.createPool({
    host: process.env.INSTANCE_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 20000,
    queueLimit: 0,
  });

  if (process.env.NODE_ENV === "production") {
    pool.socketPath = process.env.DB_SOCKET_PATH;
  } else {
    pool.host = process.env.INSTANCE_HOST;
  }
} catch (error) {
  console.error("Error creating database connection pool:", error);
  process.exit(1);
}

module.exports = pool; 