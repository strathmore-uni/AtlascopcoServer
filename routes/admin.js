const express = require("express");
const router = express.Router();
const pool = require("../config/database");
const { getAdminPermissions } = require("../middleware/auth");

// Get order count for admin dashboard
router.get("/orders/count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let orderCountQuery = "SELECT COUNT(*) AS count FROM placing_orders";
    let queryParams = [];

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      orderCountQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    const [currentRows] = await pool.query(orderCountQuery, queryParams);
    const currentCount = currentRows[0].count;

    let previousOrderCountQuery = `
      SELECT COUNT(*) AS count
      FROM placing_orders
      WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    `;

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      previousOrderCountQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    const [previousRows] = await pool.query(previousOrderCountQuery, queryParams);
    const previousCount = previousRows[0].count;

    const percentageIncrease = previousCount > 0
      ? ((currentCount - previousCount) / previousCount) * 100
      : 0;

    res.json({
      count: currentCount,
      percentageIncrease: percentageIncrease.toFixed(2),
    });
  } catch (error) {
    console.error("Error fetching order count:", error);
    res.status(500).json({ error: "Error fetching order count" });
  }
});

// Get product count
router.get("/products/count", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT COUNT(*) AS count FROM fulldata");
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching product count:", error);
    res.status(500).json({ error: "Error fetching product count" });
  }
});

// Get user count
router.get("/users/count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let userCountQuery = "SELECT COUNT(*) AS count FROM registration";
    let queryParams = [];

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      userCountQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    const [rows] = await pool.query(userCountQuery, queryParams);
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching user count:", error);
    res.status(500).json({ error: "Error fetching user count" });
  }
});

// Get recent orders
router.get("/orders/recent", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    let getOrdersQuery = `
      SELECT po.id, po.ordernumber, po.created_at, po.status, r.email
      FROM placing_orders po
      LEFT JOIN registration r ON po.email = r.email
      WHERE po.created_at >= ?
    `;

    let queryParams = [sevenDaysAgo];

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getOrdersQuery += " AND r.country = ?";
      queryParams.push(adminCountryCode);
    }

    const [recentOrders] = await pool.query(getOrdersQuery, queryParams);

    if (recentOrders.length === 0) {
      return res.status(404).json({ message: "No recent orders found" });
    }

    res.status(200).json(recentOrders);
  } catch (error) {
    console.error("Error fetching recent orders:", error);
    res.status(500).json({ error: "Failed to fetch recent orders" });
  }
});

// Get pending orders
router.get("/orders/pending", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let getOrdersQuery = `
      SELECT placing_orders.*, 
             JSON_ARRAYAGG(
               JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)
             ) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Pending'
    `;

    let queryParams = [];

    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    if (startDate) {
      getOrdersQuery += " AND placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate));
    }

    if (endDate) {
      getOrdersQuery += " AND placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate));
    }

    getOrdersQuery += " GROUP BY placing_orders.id";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: Array.isArray(order.items) ? order.items : JSON.parse(order.items || "[]"),
      ordernumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Error fetching pending orders" });
  }
});

// Update order status
router.patch("/orders/:orderId/status", async (req, res) => {
  const orderId = req.params.orderId;
  const { status, userEmail } = req.body;

  if (!userEmail || !status) {
    return res.status(400).json({ message: "Invalid request data" });
  }

  try {
    const [adminResult] = await pool.query(
      "SELECT id FROM registration WHERE email = ?",
      [userEmail]
    );

    if (adminResult.length === 0) {
      return res.status(404).json({ message: "Admin not found" });
    }

    const adminId = adminResult[0].id;

    const [permissionsResult] = await pool.query(
      "SELECT * FROM admin_rights WHERE user_id = ?",
      [adminId]
    );

    if (permissionsResult.length === 0) {
      return res.status(404).json({ message: "Admin permissions not found" });
    }

    const currentAdmin = permissionsResult[0];

    if (!currentAdmin.manage_orders_permission) {
      return res.status(403).json({ message: "Forbidden: You do not have permission to manage orders" });
    }

    const [updateResult] = await pool.query(
      "UPDATE placing_orders SET status = ? WHERE id = ?",
      [status, orderId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    const [orderResult] = await pool.query(
      "SELECT email, ordernumber FROM placing_orders WHERE id = ?",
      [orderId]
    );

    if (orderResult.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    const { email: userOrderEmail, ordernumber } = orderResult[0];

    await pool.query(
      "INSERT INTO usernotifications (email, message) VALUES (?, ?)",
      [`${userOrderEmail}`, `Your order ${ordernumber} has been updated to ${status}`]
    );

    res.status(200).json({
      message: "Order status updated and notification sent successfully",
    });
  } catch (error) {
    console.error("Error updating order status:", error);
    res.status(500).json({ error: "Error updating order status" });
  }
});

// Get registered users
router.get("/users/registered", async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let getUsersQuery = "SELECT * FROM registration";
    const queryParams = [];

    if (adminRole !== "superadmin") {
      getUsersQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    if (filterCountry) {
      if (adminRole === "superadmin") {
        getUsersQuery += queryParams.length > 0 ? " AND country = ?" : " WHERE country = ?";
      } else {
        getUsersQuery += " AND country = ?";
      }
      queryParams.push(filterCountry);
    }

    const [users] = await pool.query(getUsersQuery, queryParams);
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get new registered users
router.get("/users/new", async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country;
  const daysAgo = 14;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    const date14DaysAgo = new Date();
    date14DaysAgo.setDate(date14DaysAgo.getDate() - daysAgo);
    const formattedDate = date14DaysAgo.toISOString().split("T")[0];

    let getUsersQuery = "SELECT * FROM registration WHERE registration_date >= ?";
    let queryParams = [formattedDate];

    if (adminRole !== "superadmin") {
      getUsersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    if (filterCountry) {
      getUsersQuery += " AND country = ?";
      queryParams.push(filterCountry);
    }

    const [users] = await pool.query(getUsersQuery, queryParams);
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get monthly user growth
router.get("/users/monthly-growth", async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let getUsersQuery = `
      SELECT DATE_FORMAT(registration_date, '%Y-%m') AS month, COUNT(*) AS userCount
      FROM registration
      WHERE registration_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
    `;
    let queryParams = [];

    if (adminRole !== "superadmin") {
      getUsersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    if (filterCountry) {
      getUsersQuery += " AND country = ?";
      queryParams.push(filterCountry);
    }

    getUsersQuery += " GROUP BY month ORDER BY month";

    const [monthlyUsers] = await pool.query(getUsersQuery, queryParams);
    res.json(monthlyUsers);
  } catch (error) {
    console.error("Error fetching monthly user growth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get notifications
router.get("/notifications", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const adminDetailsQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminDetailsResult] = await pool.query(adminDetailsQuery, [adminEmail]);

    if (adminDetailsResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = adminDetailsResult[0];

    let getNotificationsQuery = `SELECT * FROM notifications`;
    let queryParams = [];

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getNotificationsQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    getNotificationsQuery += " ORDER BY created_at DESC";

    const [notifications] = await pool.query(getNotificationsQuery, queryParams);

    if (notifications.length === 0) {
      return res.status(404).json({ message: "No notifications found" });
    }

    const formattedNotifications = notifications.map((notification) => ({
      ...notification,
    }));

    res.status(200).json(formattedNotifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

// Get notification count
router.get("/notifications/count", async (req, res) => {
  const adminEmail = req.query.email;
  try {
    if (!adminEmail) {
      return res.status(401).json({ error: "Unauthorized: No email provided" });
    }

    const [adminResult] = await pool.query(
      "SELECT country, role FROM registration WHERE email = ?",
      [adminEmail]
    );

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    let countQuery;
    let queryParams = [];

    if (adminRole === "superadmin") {
      countQuery = "SELECT COUNT(*) AS count FROM notifications WHERE status = 'unread'";
    } else {
      countQuery = "SELECT COUNT(*) AS count FROM notifications WHERE status = 'unread' AND country = ?";
      queryParams.push(adminCountry);
    }

    const [notificationCountResult] = await pool.query(countQuery, queryParams);
    res.json({ count: notificationCountResult[0].count });
  } catch (error) {
    console.error("Error fetching notifications count:", error);
    res.status(500).json({ error: "Error fetching notifications count" });
  }
});

// Mark notification as read
router.patch("/notifications/:id/read", async (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  const connection = await pool.getConnection();
  try {
    const notificationQuery = "SELECT country FROM notifications WHERE id = ?";
    const [notificationResult] = await connection.query(notificationQuery, [id]);

    if (notificationResult.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    const notificationCountry = notificationResult[0].country;

    const adminQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminResult] = await connection.query(adminQuery, [email]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    if (adminRole !== "superadmin" && notificationCountry !== adminCountry) {
      return res.status(403).json({
        error: "Forbidden: Notification not relevant to your country",
      });
    }

    await connection.query(
      "UPDATE notifications SET status = 'read' WHERE id = ?",
      [id]
    );

    res.json({ message: "Notification marked as read" });
  } catch (error) {
    console.error("Error marking notification as read:", error);
    res.status(500).json({ error: "Error marking notification as read" });
  } finally {
    connection.release();
  }
});

// Delete notification
router.delete("/notifications/:id", async (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  const connection = await pool.getConnection();
  try {
    const notificationQuery = "SELECT country FROM notifications WHERE id = ?";
    const [notificationResult] = await connection.query(notificationQuery, [id]);

    if (notificationResult.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    const notificationCountry = notificationResult[0].country;

    const adminQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminResult] = await connection.query(adminQuery, [email]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    if (adminRole !== "superadmin" && notificationCountry !== adminCountry) {
      return res.status(403).json({
        error: "Forbidden: Notification not relevant to your country",
      });
    }

    await connection.query("DELETE FROM notifications WHERE id = ?", [id]);
    res.json({ message: "Notification deleted" });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({ error: "Error deleting notification" });
  } finally {
    connection.release();
  }
});

module.exports = router; 