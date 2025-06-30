const express = require("express");
const router = express.Router();
const pool = require("../config/database");
const { 
  hashPassword, 
  comparePassword, 
  generateToken, 
  logAudit,
  getAdminPermissions 
} = require("../middleware/auth");
const { validateRegistration, validateLogin } = require("../middleware/validation");

// User registration
router.post("/register", validateRegistration, async (req, res) => {
  const {
    companyName,
    title,
    firstName,
    secondName,
    address1,
    address2,
    city,
    zip,
    phone,
    email,
    password,
    country,
  } = req.body;

  const normalizedEmail = email.toLowerCase();
  const adminEmail = req.user?.email || "unknown";

  try {
    // Check if email already exists
    const checkEmailQuery = "SELECT email FROM registration WHERE LOWER(email) = LOWER(?)";
    const [result] = await pool.query(checkEmailQuery, [normalizedEmail]);

    if (result.length > 0) {
      console.error("Email already exists:", normalizedEmail);
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash the password
    const hashedPassword = await hashPassword(password);

    // Insert user into the registration table
    const insertQuery = `
      INSERT INTO registration (
        companyName, title, firstName, secondName, address1, address2, city, zip, phone, email, password, country
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    `;
    const values = [
      companyName,
      title,
      firstName,
      secondName,
      address1,
      address2,
      city,
      zip,
      phone,
      normalizedEmail,
      hashedPassword,
      country,
    ];

    await pool.query(insertQuery, values);

    // Insert notification for admin
    const notificationQuery = `
      INSERT INTO notifications (message, country, created_at) 
      VALUES (?, ?, NOW())
    `;
    const notificationMessage = `New user registered: ${normalizedEmail}, Country: ${country}`;
    await pool.query(notificationQuery, [notificationMessage, country]);

    // Insert audit log
    await logAudit({
      email: normalizedEmail,
      action: `Registered new user: ${normalizedEmail}`,
      success: 1,
      ipAddress: req.ip || "unknown"
    });

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Server error:", err);

    // Insert audit log for failed registration
    await logAudit({
      email: normalizedEmail,
      action: `Failed to register new user: ${normalizedEmail}`,
      success: 0,
      ipAddress: req.ip || "unknown"
    });

    res.status(500).json({ error: "Server error" });
  }
});

// User login
router.post("/login", validateLogin, async (req, res) => {
  const { email, password } = req.body;

  console.log('Login attempt with email:', email);

  try {
    const sql = "SELECT * FROM registration WHERE email = ?";
    const [users] = await pool.query(sql, [email]);

    if (users.length > 0) {
      const user = users[0];

      // Check if the user is suspended
      if (user.is_suspended) {
        return res.status(403).json({ message: "Account suspended" });
      }

      // Compare the provided password with the hashed password
      const passwordMatch = await comparePassword(password, user.password);

      if (passwordMatch) {
        const isAdmin = user.role === "superadmin";
        const isMiniAdmin = user.role === "admin";
        const isWarehouse = user.role === "warehouse";
        const isFinance = user.role === "finance";

        // Create JWT token
        const token = generateToken({
          email: user.email,
          isAdmin: isAdmin,
          isMiniAdmin: isMiniAdmin,
          isWarehouse: isWarehouse,
          isFinance: isFinance,
          country: user.country,
        });

        // Log successful login
        await logAudit({
          email,
          action: "Login",
          success: true
        });

        // Insert login record into logins table
        const insertLoginSql = "INSERT INTO logins (user_id, login_time, email, status) VALUES (?, NOW(), ?, ?)";
        await pool.query(insertLoginSql, [user.id, user.email, 'online']);

        return res.json({
          message: "Login Successful",
          token,
          isAdmin: isAdmin,
          isMiniAdmin: isMiniAdmin,
          isWarehouse: isWarehouse,
          isFinance: isFinance,
          country: user.country
        });
      } else {
        console.log('Login failed for email:', email);

        // Log failed login due to incorrect password
        await logAudit({
          email,
          action: "Login",
          success: false
        });

        return res.status(401).json({ message: "Login Failed: Incorrect Password" });
      }
    } else {
      console.log('Login failed: Email not found', email);

      // Log failed login due to email not found
      await logAudit({
        email,
        action: "Login",
        success: false
      });

      return res.status(401).json({ message: "Login Failed: Email Not Found" });
    }
  } catch (error) {
    console.error("Error during login:", error);

    // Log failed login due to error
    await logAudit({
      email,
      action: "Login",
      success: false
    });

    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Get user profile
router.get("/profile", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const query = `
      SELECT email, companyName, title, firstName, secondName, address1, address2, city, zip, phone, country
      FROM registration
      WHERE email = ?
    `;
    const [userResults] = await pool.query(query, [userEmail]);

    if (userResults.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userData = userResults[0];
    res.json({
      email: userData.email,
      companyName: userData.companyName,
      title: userData.title,
      firstName: userData.firstName,
      secondName: userData.secondName,
      address1: userData.address1,
      address2: userData.address2,
      city: userData.city,
      zip: userData.zip,
      phone: userData.phone,
      country: userData.country,
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update user profile
router.put("/profile", async (req, res) => {
  const {
    email,
    companyName,
    title,
    firstName,
    secondName,
    address1,
    address2,
    city,
    zip,
    phone,
    country,
  } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const query = `
      UPDATE registration
      SET companyName = ?, title = ?, firstName = ?, secondName = ?, address1 = ?,
          address2 = ?, city = ?, zip = ?, phone = ?, country = ?
      WHERE email = ?
    `;
    const values = [
      companyName,
      title,
      firstName,
      secondName,
      address1,
      address2,
      city,
      zip,
      phone,
      country,
      email,
    ];

    const [result] = await pool.query(query, values);

    if (result.affectedRows > 0) {
      res.json({ message: "User details updated successfully" });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.error("Error updating user data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Reset password
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ message: 'Email and new password are required' });
  }

  try {
    // Hash the new password
    const hashedPassword = await hashPassword(newPassword);

    // Update the password in the database
    const result = await pool.query(
      'UPDATE registration SET password = ? WHERE email = ?',
      [hashedPassword, email]
    );

    // Check if any rows were updated
    if (result[0].affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Successfully updated
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'An error occurred while resetting the password' });
  }
});

// Logout
router.post("/logout", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const sql = "DELETE FROM logins WHERE email = ?";

  try {
    await pool.query(sql, [email]);
    return res.json({ message: "User logged out and record deleted successfully" });
  } catch (error) {
    console.error("Error logging out user:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Verify token
router.post("/verify-token", (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  const jwt = require("jsonwebtoken");
  const secretKey = process.env.JWT_SECRET;

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    res.json({
      email: decoded.email,
      isAdmin: decoded.isAdmin,
      country: decoded.country,
    });
  });
});

// Verify token endpoint
router.post("/verifyToken", async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(401).json({ valid: false, message: "Token required" });
  }

  try {
    const jwt = require('jsonwebtoken');
    const secretKey = process.env.JWT_SECRET || 'your-secret-key';
    
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.status(401).json({ valid: false, message: "Invalid token" });
      }
      
      res.json({
        valid: true,
        user: {
          email: decoded.email,
          isAdmin: decoded.isAdmin,
          isMiniAdmin: decoded.isMiniAdmin,
          isWarehouse: decoded.isWarehouse,
          isFinance: decoded.isFinance,
          country: decoded.country,
        }
      });
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(500).json({ valid: false, message: "Internal server error" });
  }
});

module.exports = router; 