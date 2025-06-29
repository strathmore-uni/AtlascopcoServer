const express = require("express");
const router = express.Router();
const pool = require("../config/database");
const { validateOrder } = require("../middleware/validation");

// Create new order
router.post("/", validateOrder, async (req, res) => {
  const { formData, cartItems, orderNumber, newPrice } = req.body;

  if (!formData || !cartItems || !orderNumber || !newPrice) {
    return res.status(400).json({
      error: "Missing form data, cart items, order number, or new price",
    });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // Insert new order
    const [orderResult] = await connection.query(
      `INSERT INTO placing_orders 
         (company_name, title, first_name, second_name, address1, address2, city, zip, phone, email, ordernumber, status, totalprice, country) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)`,
      [
        formData.companyName,
        formData.title,
        formData.firstName,
        formData.secondName,
        formData.address1,
        formData.address2,
        formData.city,
        formData.zip,
        formData.phone,
        formData.email,
        orderNumber,
        newPrice,
        formData.country,
      ]
    );

    // Insert order items
    for (const item of cartItems) {
      await connection.query(
        `INSERT INTO order_items (order_id, description, partnumber, price, quantity) 
         VALUES (?, ?, ?, ?, ?)`,
        [
          orderResult.insertId,
          item.description,
          item.partnumber,
          item.price,
          item.quantity,
        ]
      );
    }

    // Insert notification for admin
    const notificationQuery = `
      INSERT INTO notifications (message, country, created_at) 
      VALUES (?, ?, NOW())
    `;
    const notificationMessage = `New order placed: Order Number: ${orderNumber}, Email: ${formData.email}, Country: ${formData.country}`;
    await connection.query(notificationQuery, [
      notificationMessage,
      formData.country,
    ]);

    await connection.commit();
    res.json({ message: "Order placed successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error processing order:", error);
    res.status(500).json({ error: "Error processing order" });
  } finally {
    connection.release();
  }
});

// Get order history for a user
router.get("/history", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [orders] = await pool.query(
      `SELECT placing_orders.*, 
              JSON_ARRAYAGG(
                JSON_OBJECT(
                  'description', oi.description, 
                  'quantity', oi.quantity, 
                  'price', oi.price
                )
              ) as items
       FROM placing_orders
       LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
       WHERE placing_orders.email = ?
       GROUP BY placing_orders.id`,
      [userEmail]
    );

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found for this email" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});

// Get specific order details
router.get("/:orderId", async (req, res) => {
  const orderId = req.params.orderId;

  if (!orderId) {
    return res.status(400).json({ error: "Order ID parameter is required" });
  }

  try {
    const [orderDetails] = await pool.query(
      `SELECT placing_orders.*, JSON_ARRAYAGG(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
       FROM placing_orders
       LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
       WHERE placing_orders.id = ?
       GROUP BY placing_orders.id`,
      [orderId]
    );

    if (orderDetails.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }
    const formattedOrder = {
      ...orderDetails[0],
      items: orderDetails[0].items || [],
    };

    res.status(200).json(formattedOrder);
  } catch (error) {
    console.error("Error fetching order details:", error);
    res.status(500).json({ error: "Error fetching order details" });
  }
});

// Get order history by email (legacy endpoint)
router.get("/order-history/:email", (req, res) => {
  const { email } = req.params;
  console.log(`Received request for order history: ${email}`);

  const query = `SELECT * FROM placing_orders WHERE email = ?`;

  console.log(`Executing query: ${query} with email: ${email}`);

  pool.query(query, [email], (err, results) => {
    console.log('Query executed');

    if (err) {
      console.error('Error fetching orders:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    console.log('Fetched Results:', results);

    if (results.length === 0) {
      return res.status(404).json({ message: 'No orders found for this email.' });
    }

    console.log('Sending response to client');
    res.json(results);
  });
});

module.exports = router; 