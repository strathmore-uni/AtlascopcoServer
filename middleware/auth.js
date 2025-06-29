const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const pool = require("../config/database");

const secretKey = process.env.JWT_SECRET;

// Middleware to authenticate JWT tokens
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: Token missing" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, secretKey);

    req.user = decoded;
    console.log("Authenticated user:", req.user);

    next();
  } catch (err) {
    console.error("Authentication error:", err);
    res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
};

// Function to hash passwords
const hashPassword = async (password, saltRounds = 10) => {
  return await bcrypt.hash(password, saltRounds);
};

// Function to compare passwords
const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Function to generate JWT token
const generateToken = (userData) => {
  return jwt.sign(userData, secretKey, { expiresIn: "7d" });
};

// Function to log audit events
const logAudit = async ({ email, action, success, ipAddress = "unknown" }) => {
  const sql = `
    INSERT INTO audit_logs (email, action, success, ip_address, timestamp) 
    VALUES (?, ?, ?, ?, NOW())
  `;
  try {
    await pool.query(sql, [email, action, success, ipAddress]);
  } catch (err) {
    console.error("Error logging audit:", err);
  }
};

// Function to get admin permissions
const getAdminPermissions = async (userEmail) => {
  const query = `
    SELECT create_permission, update_permission, read_permission, delete_permission, manage_clearorder_permission
    FROM admin_rights
    JOIN registration ON registration.id = admin_rights.user_id
    WHERE registration.email = ?
  `;
  
  try {
    const [results] = await pool.query(query, [userEmail]);

    if (!results || results.length === 0) {
      console.error("No admin rights found for the user:", userEmail);
      return null;
    }

    return results[0];
  } catch (error) {
    console.error("Error fetching admin permissions:", error);
    return null;
  }
};

module.exports = {
  authenticate,
  hashPassword,
  comparePassword,
  generateToken,
  logAudit,
  getAdminPermissions,
  secretKey
}; 