const express = require("express");
const router = express.Router();
const pool = require("../config/database");

// Get cart items for a user
router.get("/", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [rows] = await pool.query(`SELECT * FROM cart WHERE user_email = ?`, [userEmail]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "No cart items found for this email" });
    }

    res.status(200).json(rows);
  } catch (error) {
    console.error("Error fetching cart items:", error);
    res.status(500).json({ error: "Error fetching cart items" });
  }
});

// Add single item to cart
router.post("/single", async (req, res) => {
  const { userEmail, partnumber, quantity, description, price } = req.body;

  if (!userEmail || !partnumber || !quantity || !description || !price) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    await pool.query(
      `INSERT INTO cart (user_email, partnumber, quantity, description, price)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE 
       quantity = quantity + VALUES(quantity), 
       description = VALUES(description), 
       price = VALUES(price)`,
      [userEmail, partnumber, quantity, description, price]
    );

    res.json({ message: "Product added to cart" });
  } catch (error) {
    console.error("Error adding product to cart:", error);
    res.status(500).json({ error: "Error adding product to cart" });
  }
});

// Add order items to cart
router.post("/from-order", async (req, res) => {
  const { userEmail, orderId } = req.body;

  if (!userEmail || !orderId) {
    return res.status(400).json({ error: "User email and order ID are required" });
  }

  try {
    // Fetch items from the order
    const [orderItems] = await pool.query(
      `SELECT partnumber, quantity, description, price
       FROM order_items 
       WHERE order_id = ?`,
      [orderId]
    );

    // If no items found in the order
    if (orderItems.length === 0) {
      return res.status(404).json({ error: "No items found in the order" });
    }

    // Insert or update cart items in bulk
    const values = orderItems.map((item) => [
      userEmail,
      item.partnumber,
      item.quantity,
      item.description,
      item.price,
      item.image,
    ]);

    // Generating the query dynamically
    const placeholders = values.map(() => "(?,?,?,?,?,?)").join(",");
    const sql = `
      INSERT INTO cart (user_email, partnumber, quantity, description, price, image)
      VALUES ${placeholders}
      ON DUPLICATE KEY UPDATE 
        quantity = quantity + VALUES(quantity), 
        description = VALUES(description), 
        price = VALUES(price), 
        image = VALUES(image)`;

    // Flatten the array of values for the query
    const flatValues = values.flat();

    await pool.query(sql, flatValues);

    res.json({ message: "Order items added to cart" });
  } catch (error) {
    console.error("Error adding order items to cart:", error);
    res.status(500).json({ error: "Error adding order items to cart" });
  }
});

// Remove single item from cart
router.delete("/:partnumber", async (req, res) => {
  const userEmail = req.query.email;
  const { partnumber } = req.params;

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [result] = await pool.query(
      "DELETE FROM cart WHERE user_email = ? AND partnumber = ?",
      [userEmail, partnumber]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Item not found in cart" });
    }

    res.json({ message: "Item removed from cart" });
  } catch (error) {
    console.error("Error removing item from cart:", error);
    res.status(500).json({ error: "Error removing item from cart" });
  }
});

// Clear entire cart
router.delete("/", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [result] = await pool.query("DELETE FROM cart WHERE user_email = ?", [userEmail]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "No items found in cart to clear" });
    }

    res.json({ message: "Cart cleared" });
  } catch (error) {
    console.error("Error clearing cart:", error);
    res.status(500).json({ error: "Error clearing cart" });
  }
});

module.exports = router; 