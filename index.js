const express = require("express");
const mysql = require("mysql2/promise");
const app = express();
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
require("dotenv").config();

const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

{/** 
app.use(function (req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE,PATCH,OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});*/}
app.use(cors({
  origin: 'https://localhost:3000', // Allow requests from your frontend origin
  methods: 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
  allowedHeaders: 'Content-Type,Authorization' // Allow Authorization header
}));

app.use(express.json());

const loggedInUsers = new Set();

salt = 10;

const secretKey = process.env.JWT_SECRET;
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
} catch (error) {
  console.error("Error creating database connection pool:", error);
  process.exit(1); // Exit the process or handle the error as appropriate
}

{
  /** 
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'atlascorpobusiness/build')));
socketPath: process.env.DB_SOCKET_PATH,
*/
}
app.get("/", (req, res) => {
  res.send("Hello World!");
});

if (process.env.NODE_ENV === "production") {
  pool.socketPath = process.env.DB_SOCKET_PATH;
} else {
  pool.host = process.env.INSTANCE_HOST;
}
//////////////////////////////////////////users////////////////////////////////////////////
app.post("/api/cart", async (req, res) => {
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
    const values = orderItems.map(item => [
      userEmail, item.partnumber, item.quantity, item.description, item.price, item.image
    ]);

    // Generating the query dynamically
    const placeholders = values.map(() => '(?,?,?,?,?,?)').join(',');
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
app.post("/api/singlecart", async (req, res) => {
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

app.get("/api/cart", async (req, res) => {
  const userEmail = req.query.email; // Get email from query parameter

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    // Query the cart items for the given email
    const [rows] = await pool.query(`SELECT * FROM cart WHERE user_email = ?`, [
      userEmail,
    ]);

    // If no cart items found, return an empty array
    if (rows.length === 0) {
      return res
        .status(404)
        .json({ message: "No cart items found for this email" });
    }

    // Respond with the fetched cart items
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error fetching cart items:", error);
    res.status(500).json({ error: "Error fetching cart items" });
  }
});

app.delete("/api/cart/:partnumber", async (req, res) => {
  const userEmail = req.query.email; // Get email from query parameter
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

app.delete("/api/cart", async (req, res) => {
  const userEmail = req.query.email; // Get email from query parameter

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [result] = await pool.query("DELETE FROM cart WHERE user_email = ?", [
      userEmail,
    ]);

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "No items found in cart to clear" });
    }

    res.json({ message: "Cart cleared" });
  } catch (error) {
    console.error("Error clearing cart:", error);
    res.status(500).json({ error: "Error clearing cart" });
  }
});

app.get("/api/cart", async (req, res) => {
  const { userId } = req.user;

  try {
    const [rows] = await db.query(
      "SELECT c.partnumber, c.quantity, p.Description, p.Price, p.image FROM cart c JOIN products p ON c.partnumber = p.partnumber WHERE c.user_id = ?",
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: "Error fetching cart items" });
  }
});
app.get("/api/user/notifications", async (req, res) => {
  const email = req.query.email;

  try {
    // Fetch notifications
    const [notifications] = await pool.query(
      "SELECT id, message FROM usernotifications WHERE email = ?",
      [email]
    );

    // Fetch order numbers if needed
    const notificationsWithOrderNumber = await Promise.all(
      notifications.map(async (notification) => {
        // Assuming you have some way to determine the order id from the notification or fetch it separately
        // If you don't have orderId, you might need to adjust how you get the order number
        // Example: Fetch order number directly if you have a way to relate notifications to orders
        const [orderResult] = await pool.query(
          "SELECT orderNumber FROM placing_orders WHERE email = ? AND id = ?",
          [email, notification.id] // Adjust if you have a way to map notification id to order id
        );

        return {
          ...notification,
          orderNumber: orderResult.length ? orderResult[0].orderNumber : "N/A",
        };
      })
    );

    res.status(200).json(notificationsWithOrderNumber);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

const validateInput = (req, res, next) => {
  const schema = Joi.object({
    companyName: Joi.string().required(),
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    secondName: Joi.string().required(),
    address1: Joi.string().required(),
    address2: Joi.string().optional(),
    city: Joi.string().required(),
    zip: Joi.string().required(),
    phone: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    confpassword: Joi.string().valid(Joi.ref("password")).required(),
    country: Joi.string().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    console.error("Validation error:", error.details);
    return res.status(400).json({ error: error.details });
  }
  next();
};

app.post("/api/register", validateInput, async (req, res) => {
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

  try {
    const checkEmailQuery =
      "SELECT email FROM registration WHERE LOWER(email) = LOWER(?)";
    const [result] = await pool.query(checkEmailQuery, [normalizedEmail]);

    if (result.length > 0) {
      console.error("Email already exists:", normalizedEmail);
      return res.status(400).json({ error: "Email already exists" });
    }

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
      password,
      country,
    ];

    await pool.query(insertQuery, values);

    // Insert notification for admin
    const notificationQuery = `
      INSERT INTO notifications (message, created_at) 
      VALUES (?, NOW())
    `;
    const notificationMessage = `New user registered: ${normalizedEmail}`;
    await pool.query(notificationQuery, [notificationMessage]);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
app.get("/verify-email", (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const query = "UPDATE registration SET is_verified = 1 WHERE email = ?";

  pool.query(query, [email], (err, result) => {
    if (err) {
      console.error("Error updating email verification:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Email not found" });
    }

    return res.status(200).json({ message: "Email verified successfully" });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM registration WHERE email = ? AND password = ?";
  const email = req.body.email;
  const password = req.body.password;

  console.log('Login attempt with email:', email);

  pool.query(sql, [email, password])
    .then(([users]) => {
      if (users.length > 0) {
        const user = users[0];
        const isAdmin = user.role === "superadmin";
        const isMiniAdmin = user.role === "admin";
        const token = jwt.sign(
          { 
            email: user.email, 
            isAdmin: isAdmin, 
            isMiniAdmin: isMiniAdmin, 
            country: user.country, // Include country in the token
           
          }, 
          secretKey, 
          { expiresIn: "1h" }
        );

        return res.json({
          message: "Login Successful",
          token,
          isAdmin: isAdmin,
          isMiniAdmin: isMiniAdmin,
          country: user.country // Include country in the response
        });
      } else {
        console.log('Login failed for email:', email);
        return res.status(401).json({ message: "Login Failed" });
      }
    })
    .catch((err) => {
      console.error("Error during login:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    });
});





app.post("/verifyToken", (req, res) => {
  const token = req.body.token;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    res.json({ email: decoded.email, isAdmin: decoded.isAdmin, country: decoded.country });
  });
});

app.use((req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (!err) {
        loggedInUsers.add({
          email: decoded.email,
          isAdmin: decoded.isAdmin,
          country: decoded.country,
        });
      }
    });
  }
  next();
});

app.get("/api/myproducts", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    const productsQuery = `
      SELECT p.id, p.partnumber, p.Description, p.image, p.thumb1, p.thumb2, 
             pp.price AS Price, pp.stock_quantity AS Stock
      FROM fulldata p
      JOIN product_prices pp ON p.id = pp.product_id
      WHERE pp.country_code = ?
    `;
    const [products] = await pool.query(productsQuery, [userCountryCode]);

    console.log(`Fetched ${products.length} products`);
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/api/products/:category?", async (req, res) => {
  const category = req.params.category;
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    let query;
    let queryParams = [userCountryCode];

    if (category) {
      query = `
          SELECT p.id, p.partnumber, p.Description, p.image, p.thumb1, p.thumb2, 
                 pp.price AS Price, pp.stock_quantity AS Stock
          FROM fulldata p
          JOIN product_prices pp ON p.id = pp.product_id
          WHERE (p.mainCategory = ? OR p.subCategory = ?) AND pp.country_code = ?
        `;
      queryParams = [category, category, userCountryCode];
    } else {
      query = `
          SELECT p.id, p.partnumber, p.Description, p.image, p.thumb1, p.thumb2, 
                 pp.price AS Price, pp.stock_quantity AS Stock
          FROM fulldata p
          JOIN product_prices pp ON p.id = pp.product_id
          WHERE pp.country_code = ?
        `;
    }

    const [results] = await pool.query(query, queryParams);
    console.log(`Fetched ${results.length} products`);
    res.json(results);
  } catch (err) {
    console.error("Error fetching products:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/order", async (req, res) => {
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
         (company_name, title, first_name, second_name, address1, address2, city, zip, phone, email, ordernumber, status, totalprice,country) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?,?)`,
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
          orderResult.insertId, // Use the newly created order ID
          item.description,
          item.partnumber,
          item.price,
          item.quantity
        ]
      );
    }

    await connection.commit();
    res.json({ message: 'Order placed successfully' });
  } catch (error) {
    await connection.rollback();
    console.error('Error processing order:', error);
    res.status(500).json({ error: 'Error processing order' });
  } finally {
    connection.release();
  }
});


app.get("/api/orders", async (req, res) => {
  const userId = req.query.userId;
  const query = "SELECT * FROM orders WHERE userId = ? ORDER BY orderDate DESC";

  try {
    const [results] = await pool.query(query, [userId]);
    res.json(results);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).send("Error fetching orders");
  }
});
app.get("/api/orders/history", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const [orders] = await pool.query(
      `SELECT placing_orders.*, GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
       FROM placing_orders
       LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
       WHERE placing_orders.email = ?
       GROUP BY placing_orders.id`,
      [userEmail]
    );

    // If no orders found, return an empty array
    if (orders.length === 0) {
      return res
        .status(404)
        .json({ message: "No orders found for this email" });
    }

    // Parse items JSON and format response
    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
    }));

    // Respond with the fetched orders
    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});

app.get("/api/orders/:orderId", async (req, res) => {
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

app.get("/api/search", async (req, res) => {
  const searchTerm = req.query.term || "";
  const category = req.query.category || "";
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Retrieve the user's country code based on the provided email
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    // Prepare the search query
    let query = `
      SELECT 
        p.id, 
        p.partnumber, 
        p.Description, 
        p.image, 
        p.thumb1, 
        p.thumb2, 
        pp.price AS Price, 
        pp.stock_quantity AS quantity, 
        p.subCategory AS category
      FROM 
        fulldata p
      JOIN 
        product_prices pp ON p.id = pp.product_id
      WHERE 
        pp.country_code = ? 
      AND 
        (p.partnumber LIKE ? OR p.Description LIKE ? OR p.mainCategory LIKE ?)
    `;

    const searchValue = `%${searchTerm}%`;
    const queryParams = [
      userCountryCode,
      searchValue,
      searchValue,
      searchValue,
    ];

    // Add category filter if specified
    if (category) {
      query += " AND (p.mainCategory = ? OR p.subCategory = ?)";
      queryParams.push(category, category);
    }

    // Execute the search query
    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error("Error executing search query:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/api/products/partnumber/:partnumber", async (req, res) => {
  const { partnumber } = req.params;
  const userEmail = req.query.email;

  try {
    if (!userEmail) {
      return res.status(400).json({ message: "Email is required" });
    }

    const query = `
      SELECT p.partnumber, p.Description,p.image, pp.price AS Price
      FROM fulldata p
      JOIN atlascopcoproduct_prices pp ON p.id = pp.product_id
      JOIN registration r ON pp.country_code = r.country
      WHERE p.partnumber = ? AND r.email = ?
    `;
    const [results] = await pool.query(query, [partnumber, userEmail]);

    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: "Product not found" });
    }
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

//////////////////////////////////////users////////////////////////////////////////////////







/////////////////////////Admin//////////////////////////////////////////////
app.get("/api/admin/orders/count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let orderCountQuery = "SELECT COUNT(*) AS count FROM placing_orders";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      orderCountQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    const [rows] = await pool.query(orderCountQuery, queryParams);
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching order count:", error);
    res.status(500).json({ error: "Error fetching order count" });
  }
});

app.get("/api/admin/products/count", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT COUNT(*) AS count FROM fulldata");
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching product count:", error);
    res.status(500).json({ error: "Error fetching product count" });
  }
});



app.get("/api/admin/users/count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let userCountQuery = "SELECT COUNT(*) AS count FROM registration";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
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

app.get("/api/admin/orders/recent", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details

    // Calculate the date for seven days ago
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    // Define the base query for fetching recent orders
    let getOrdersQuery = `
      SELECT po.id, po.ordernumber, po.created_at, po.status, r.email
      FROM placing_orders po
      LEFT JOIN registration r ON po.email = r.email
      WHERE po.created_at >= ?
    `;
    
    let queryParams = [sevenDaysAgo];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " AND r.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Debugging: Log final query and parameters

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

app.get("/api/admin/orders/groupedByCountry", async (req, res) => {
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

    let getOrdersQuery = `
      SELECT po.id, po.ordernumber, po.created_at, po.status, r.email, r.country
      FROM placing_orders po
      LEFT JOIN registration r ON po.email = r.email
    `;
    
    let queryParams = [];

    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " WHERE r.country = ?";
      queryParams.push(adminCountryCode);
    }

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    const groupedOrders = orders.reduce((acc, order) => {
      if (!acc[order.country]) {
        acc[order.country] = [];
      }
      acc[order.country].push(order);
      return acc;
    }, {});

    res.status(200).json(groupedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});



app.get("/api/admin/orders/pending", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details
    console.log(`Admin Email: ${adminEmail}, Country: ${adminCountryCode}, Role: ${adminRole}`);

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Pending'
    `;
    
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";


  

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      ordernumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Error fetching pending orders" });
  }
});

app.get("/api/admin/orders/approved", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details
    console.log(`Admin Email: ${adminEmail}, Country: ${adminCountryCode}, Role: ${adminRole}`);

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Approved'
    `;
    
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";


  

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      ordernumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Error fetching pending orders" });
  }
});
app.get("/api/admin/orders/cancelled", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details
    console.log(`Admin Email: ${adminEmail}, Country: ${adminCountryCode}, Role: ${adminRole}`);

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Cancelled'
    `;
    
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";


  

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      ordernumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Error fetching pending orders" });
  }
});
app.get("/api/admin/orders/orders", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details
    console.log(`Admin Email: ${adminEmail}, Country: ${adminCountryCode}, Role: ${adminRole}`);

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items,
             placing_orders.status
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
    `;
    
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin' && adminCountryCode !== 'SUPERADMIN') {
      getOrdersQuery += " WHERE placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";

    // Debugging: Log final query and parameters

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      orderNumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});





app.post("/api/newproducts", async (req, res) => {
  const {
    partnumber,
    description,
    image,
    thumb1,
    thumb2,
    prices,
    stock,
    mainCategory,
    subCategory,
  } = req.body;

  try {
    // Insert product into the fulldata table
    const insertProductQuery = `
      INSERT INTO fulldata (partnumber, Description, image, thumb1, thumb2, mainCategory, subCategory)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const [result] = await pool.query(insertProductQuery, [
      partnumber,
      description,
      image,
      thumb1,
      thumb2,
      mainCategory,
      subCategory,
    ]);

    const productId = result.insertId;

    // Insert stock and prices into the product_prices table
    const insertPricesQuery =
      "INSERT INTO product_prices (product_id, country_code, price, stock_quantity) VALUES ?";
    const priceValues = prices.map((price) => [
      productId,
      price.country_code,
      price.price,
      stock, // assuming stock is the same for all countries
    ]);
    await pool.query(insertPricesQuery, [priceValues]);

    res.status(201).json({ message: "Product added successfully" });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/api/newproducts/batch", async (req, res) => {
  const products = req.body; // Expecting an array of products

  if (!Array.isArray(products) || products.length === 0) {
    return res.status(400).json({ error: 'Invalid products data' });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    for (const product of products) {
      const {
        partnumber,
        description,
        image,
        thumb1,
        thumb2,
        prices,
        stock,
        mainCategory,
        subCategory,
      } = product;

      // Insert product into the fulldata table
      const insertProductQuery = `
        INSERT INTO fulldata (partnumber, Description, image, thumb1, thumb2, mainCategory, subCategory)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      const [result] = await connection.query(insertProductQuery, [
        partnumber,
        description,
        image,
        thumb1,
        thumb2,
        mainCategory,
        subCategory,
      ]);

      const productId = result.insertId;

      // Insert prices into the product_prices table
      const insertPricesQuery =
        "INSERT INTO product_prices (product_id, country_code, price, stock_quantity) VALUES ?";
      const priceValues = prices.map((price) => [
        productId,
        price.country_code,
        price.price,
        stock, // assuming stock is the same for all countries
      ]);
      await connection.query(insertPricesQuery, [priceValues]);
    }

    await connection.commit();
    res.status(201).json({ message: "Products added successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error adding products:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});


app.get("/api/viewproducts", async (req, res) => {
  try {
    const productsQuery = `
      SELECT p.id, p.partnumber, p.Description, p.mainCategory,p.subCategory, p.image, p.thumb1, p.thumb2
      FROM fulldata p
    `;
    const [products] = await pool.query(productsQuery);
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/viewproducts/:id", async (req, res) => {
  const productId = req.params.id;
  try {
    const productQuery = `
      SELECT p.id, p.partnumber, p.Description, p.image, p.thumb1, p.thumb2, p.mainCategory, p.subCategory
      FROM fulldata p
      WHERE p.id = ?
    `;
    const [product] = await pool.query(productQuery, [productId]);
    const pricesQuery = `
      SELECT country_code, price, stock_quantity
      FROM product_prices
      WHERE product_id = ?
    `;
    const [prices] = await pool.query(pricesQuery, [productId]);

    if (product.length > 0) {
      res.json({ ...product[0], prices });
    } else {
      res.status(404).json({ error: "Product not found" });
    }
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/viewproducts/:id", async (req, res) => {
  const productId = req.params.id;
  const {
    partnumber,
    Description,
    image,
    thumb1,
    thumb2,
    mainCategory,
    subCategory,
    prices,
  } = req.body;

  console.log(`Received PUT request for product ID: ${productId}`);

  try {
    // Update product details in the fulldata table
    const updateProductQuery = `
      UPDATE fulldata
      SET partnumber = ?, Description = ?, image = ?, thumb1 = ?, thumb2 = ?, mainCategory = ?, subCategory = ?
      WHERE id = ?
    `;
    await pool.query(updateProductQuery, [
      partnumber,
      Description,
      image,
      thumb1,
      thumb2,
      mainCategory,
      subCategory,
      productId,
    ]);

    // Delete existing prices for the product
    const deletePricesQuery = `DELETE FROM product_prices WHERE product_id = ?`;
    await pool.query(deletePricesQuery, [productId]);

    // Insert or update prices and stock quantities
    const insertOrUpdatePricesQuery = `
      INSERT INTO product_prices (product_id, country_code, price, stock_quantity)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE price = VALUES(price), stock_quantity = VALUES(stock_quantity);
    `;
    for (const price of prices) {
      await pool.query(insertOrUpdatePricesQuery, [
        productId,
        price.country_code,
        price.price,
        price.stock_quantity,
      ]);
    }

    res.json({ message: "Product updated successfully" });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/viewproducts/:id", async (req, res) => {
  const { id } = req.params;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Delete from order_items table first if necessary

    // Delete from product_prices table
    await connection.query("DELETE FROM product_prices WHERE product_id = ?", [id]);

    // Delete from fulldata table
    await connection.query("DELETE FROM fulldata WHERE id = ?", [id]);

    await connection.commit();
    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product" });
  } finally {
    connection.release();
  }
});


app.get("/api/admin/products/near-completion", async (req, res) => {
  try {
    const [products] = await pool.query(
      `SELECT f.partnumber, f.description, pp.price, pp.stock_quantity, pp.country_code
       FROM fulldata f
       JOIN product_prices pp ON f.id = pp.product_id
       WHERE pp.stock_quantity <= 12`
    );

    if (products.length === 0) {
      return res
        .status(404)
        .json({ message: "No products near completion found" });
    }

    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products near completion:", error);
    res.status(500).json({ error: "Error fetching products near completion" });
  }
});
// Server-side code (Node.js/Express example)
app.get("/api/admin/notifications", async (req, res) => {
  try {
    const query = "SELECT * FROM notifications ORDER BY created_at DESC";
    const [notifications] = await pool.query(query);
    res.json(notifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

// Add this route to your Express server file (e.g., index.js or routes.js)
app.put("/api/admin/notifications/:id/read", async (req, res) => {
  const { id } = req.params;

  const connection = await pool.getConnection();
  try {
    await connection.query(
      `UPDATE notifications SET status = 'read' WHERE id = ?`,
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

app.get("/api/admin/notifications/count", async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const adminEmail = req.query.email;
    if (!adminEmail) {
      return res.status(400).json({ error: "Admin email is required" });
    }

    const [admin] = await connection.query(
      "SELECT country FROM registration WHERE email = ?",
      [adminEmail]
    );

    if (admin.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const adminCountry = admin[0].country;

    // Fetch the count of unread notifications for the admin's country
    const [results] = await connection.query(
      `SELECT COUNT(*) AS count FROM notifications WHERE status = 'unread' AND country = ?`,
      [adminCountry]
    );

    // Send the count as JSON response
    res.json({ count: results[0].count });
  } catch (error) {
    console.error("Error fetching notifications count:", error);
    res.status(500).json({ error: "Error fetching notifications count" });
  } finally {
    connection.release();
  }
});



app.get('/api/registeredusers', async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country; // Added filterCountry parameter

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Fetch the admin's country from the registration table
    const countryCodeQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let getUsersQuery = "SELECT * FROM registration";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== 'superadmin') {
      getUsersQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    // Apply additional country filter if provided
    if (filterCountry) {
      getUsersQuery += adminRole === 'superadmin' ? " WHERE country = ?" : " AND country = ?";
      queryParams.push(filterCountry);
    }

    const [users] = await pool.query(getUsersQuery, queryParams);

    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});



app.get("/api/registeredusers/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const [user] = await pool.query("SELECT * FROM registration WHERE id = ?", [
      userId,
    ]);

    if (user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user[0]);
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Failed to fetch user details" });
  }
});
app.get("/api/categories", async (req, res) => {
  try {
    const [categories] = await pool.query(
      "SELECT DISTINCT mainCategory FROM fulldata WHERE mainCategory IS NOT NULL"
    );
    const [subcategories] = await pool.query(
      "SELECT DISTINCT subCategory FROM fulldata WHERE subCategory IS NOT NULL"
    );
    res.json({
      categories: categories.map((cat) => cat.mainCategory),
      subcategories: subcategories.map((subcat) => subcat.subCategory),
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ error: "Failed to fetch categories" });
  }
});
app.post("/api/categories", async (req, res) => {
  const { category, subcategory } = req.body;
  try {
    if (category) {
      await pool.query(
        "INSERT IGNORE INTO fulldata (mainCategory) VALUES (?)",
        [category]
      );
    }
    if (subcategory) {
      await pool.query("INSERT IGNORE INTO fulldata (subCategory) VALUES (?)", [
        subcategory,
      ]);
    }
    res.status(200).json({ message: "Categories added successfully" });
  } catch (error) {
    console.error("Error adding categories:", error);
    res.status(500).json({ error: "Failed to add categories" });
  }
});

app.get("/api/mycategories", async (req, res) => {
  try {
    const [categories] = await pool.query(`
      SELECT DISTINCT mainCategory FROM fulldata;
    `);
    const [subCategories] = await pool.query(`
      SELECT DISTINCT subCategory FROM fulldata;
    `);
    res.json({
      mainCategories: categories.map((c) => c.mainCategory),
      subCategories: subCategories.map((c) => c.subCategory),
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ error: "Failed to fetch categories" });
  }
});

app.get("/categories/main", async (req, res) => {
  try {
    const [mainCategories] = await pool.query(
      "SELECT id, name FROM maincategories"
    );
    res.json(mainCategories);
  } catch (error) {
    console.error("Error fetching main categories:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/categories/sub", async (req, res) => {
  try {
    const [subCategories] = await pool.query(
      "SELECT id, name, mainCategoryId FROM subcategories"
    );
    res.json(subCategories);
  } catch (error) {
    console.error("Error fetching subcategories:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/admin/orders", async (req, res) => {
  try {
    const [orders] = await pool.query(
      `SELECT placing_orders.*, 
              GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items,
              placing_orders.status
       FROM placing_orders
       LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
       GROUP BY placing_orders.id`
    );

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      orderNumber: order.ordernumber,
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});

app.get("/api/admin/orders/:orderId", async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const [orders] = await pool.query(
      `SELECT placing_orders.ordernumber, placing_orders.email, placing_orders.totalprice,
              GROUP_CONCAT(JSON_OBJECT('id', oi.id, 'description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
       FROM placing_orders
       LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
       WHERE placing_orders.id = ?
       GROUP BY placing_orders.id`,
      [orderId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    const order = orders[0];
    order.items = order.items ? JSON.parse(`[${order.items}]`) : [];
    res.status(200).json(order);
  } catch (error) {
    console.error("Error fetching order details:", error);
    res.status(500).json({ error: "Error fetching order details" });
  }
});

app.patch("/api/admin/orders/:orderId/status", async (req, res) => {
  const orderId = req.params.orderId;
  const { status } = req.body;

  try {
    // Update the order status
    const [result] = await pool.query(
      "UPDATE placing_orders SET status = ? WHERE id = ?",
      [status, orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Fetch the user email associated with this order
    const [orderResult] = await pool.query(
      "SELECT email FROM placing_orders WHERE id = ?",
      [orderId]
    );

    if (orderResult.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    const userEmail = orderResult[0].email;

    // Create a notification entry
    await pool.query(
      "INSERT INTO usernotifications (email, message) VALUES (?, ?)",
      [`${userEmail}`, `Your order ${orderId} has been updated to ${status}`]
    );

    res
      .status(200)
      .json({
        message: "Order status updated and notification sent successfully",
      });
  } catch (error) {
    console.error("Error updating order status:", error);
    res.status(500).json({ error: "Error updating order status" });
  }
});


app.get("/admin/loggedInUsersCount", (req, res) => {
  const sql =
    "SELECT COUNT(DISTINCT email) AS loggedInUsers FROM registration WHERE lastLogin IS NOT NULL";
  pool
    .query(sql)
    .then(([rows]) => {
      res.json({ count: rows[0].loggedInUsers });
    })
    .catch((err) => {
      console.error("Error fetching logged-in users count:", err);
      res.status(500).json({ message: "Internal Server Error" });
    });
});
app.get("/api/admin/users/logged-in-count", (req, res) => {
  res.json({ count: loggedInUsers.size });
});


app.get("/api/user", async (req, res) => {
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

app.put("/api/user/update", async (req, res) => {
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

//////////////////////////////Admin/////////////////////////////////////////




////////////////////////////MinAdmin/////////////////////////////////////////


app.get('/api/minadmin/users/count', async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
 

    // Fetch the count of users from the same country
    const sql = "SELECT COUNT(*) AS count FROM registration WHERE country = ?";
    const [results] = await pool.query(sql, [userCountryCode]);

    res.json(results[0]);
  } catch (error) {
    console.error('Error fetching user count:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/minadmin/orders/count", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Fetch the user's country from the registration table
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    // Fetch the count of orders from placing_orders where the country matches
    const ordersCountQuery = `
      SELECT COUNT(*) AS count 
      FROM placing_orders 
      WHERE country = ?
    `;
    const [rows] = await pool.query(ordersCountQuery, [userCountryCode]);

    console.log(`Orders count for country ${userCountryCode}: ${rows[0].count}`);

    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching order count:", error);
    res.status(500).json({ error: "Error fetching order count" });
  }
});




app.get("/api/minadmin/products/count", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error("No user email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Fetch the country based on the user's email
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: "User not found" });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    // Fetch the count of products based on the user's country
    const countQuery = `
      SELECT COUNT(*) AS count
      FROM fulldata p
      JOIN product_prices pp ON p.id = pp.product_id
      WHERE pp.country_code = ?
    `;
    const [countResult] = await pool.query(countQuery, [userCountryCode]);

    res.json({ count: countResult[0].count });
  } catch (error) {
    console.error("Error fetching product count:", error);
    res.status(500).json({ error: "Error fetching product count" });
  }
});


app.get("/api/miniadmin/registeredusers", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    console.error("No admin email provided");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Fetch the admin's country from the registration table
    const countryCodeQuery = "SELECT country FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`Admin not found with email: ${adminEmail}`);
      return res.status(404).json({ error: "Admin not found" });
    }

    const adminCountryCode = countryCodeResult[0].country;
    console.log(`Admin country code: ${adminCountryCode}`);

    // Fetch registered users from the same country as the admin
    const getUsersQuery = "SELECT * FROM registration WHERE country = ?";
    const [users] = await pool.query(getUsersQuery, [adminCountryCode]);

    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});











//////////////////////////MinAdmin//////////////////////////////////////////
const port = process.env.PORT || 3001;
const server = http.createServer(app);

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

app.get("/api/test-connection", async (req, res) => {
  try {
    const [results] = await pool.query("SELECT 1 + 1 AS solution");
    res.json({ message: "Database connected", solution: results[0].solution });
  } catch (err) {
    console.error("Error executing query:", err);
    res.status(500).send(err);
  }
});
