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
const axios = require('axios');
const moment = require('moment');
const fetch = require('node-fetch');
require("dotenv").config();

// Routers
const userRoutes = require("./routes/users");
// const productRoutes = require("./routes/products");
// const orderRoutes = require("./routes/orders");
// const adminRoutes = require("./routes/admin");

const { OAuth2Client, auth } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const userSettings = {
  theme: "light",
  language: "en",
  notifications: true,
};
{
  /** 
app.use(function (req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE,PATCH,OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});*/
}
app.use(
  cors({
    origin: "https://localhost:3000", // Allow requests from your frontend origin
    methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    allowedHeaders: "Content-Type,Authorization,user-email", // Allow Authorization header
  })
);

app.use(express.json());

// Use routers
app.use("/api/users", userRoutes);
// app.use("/api/products", productRoutes);
// app.use("/api/orders", orderRoutes);
// app.use("/api/admin", adminRoutes);

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



const getAdminPermissions = async (userEmail) => {
  const query = `
    SELECT create_permission, update_permission, read_permission, delete_permission, manage_clearorder_permission
    FROM admin_rights
    JOIN registration ON registration.id = admin_rights.user_id
    WHERE registration.email = ?
  `;
  
  const [results] = await pool.query(query, [userEmail]);

  if (!results || results.length === 0) {
    console.error("No admin rights found for the user:", userEmail);
    return null; // No admin rights found
  }

  return results[0];
};



//////////////////////////////////////////users////////////////////////////////////////////
app.get('/api/questions', async (req, res) => {
  const { productId } = req.query; // productId is optional for admin

  try {
    let query = `
      SELECT q.id, q.questionText, q.userEmail, q.createdAt,
             a.id AS answerId, a.answerText, a.userEmail AS answerUserEmail, a.createdAt AS answerCreatedAt
      FROM Questions q
      LEFT JOIN Answers a ON q.id = a.questionId
    `;

    const queryParams = [];
    if (productId) {
      query += ' WHERE q.productId = ?';
      queryParams.push(productId);
    }

    query += ' ORDER BY q.createdAt DESC, a.createdAt ASC';

    const [results] = await pool.query(query, queryParams);

    // Group questions and answers (same as before)
    const groupedResults = results.reduce((acc, row) => {
      const questionIndex = acc.findIndex((q) => q.id === row.id);
      const answer = row.answerId
        ? {
            id: row.answerId,
            answerText: row.answerText,
            userEmail: row.answerUserEmail,
            createdAt: row.answerCreatedAt,
          }
        : null;

      if (questionIndex === -1) {
        acc.push({
          id: row.id,
          questionText: row.questionText,
          userEmail: row.userEmail,
          createdAt: row.createdAt,
          answers: answer ? [answer] : [],
        });
      } else {
        if (answer) {
          acc[questionIndex].answers.push(answer);
        }
      }
      return acc;
    }, []);

    res.json(groupedResults);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/api/admin/questions', async (req, res) => {
  const { productId } = req.query; // productId is optional for admin

  try {
    let query = `
      SELECT q.id, q.questionText, q.userEmail, q.createdAt,
             a.id AS answerId, a.answerText, a.userEmail AS answerUserEmail, a.createdAt AS answerCreatedAt,
             f.partnumber, f.Description
      FROM Questions q
      LEFT JOIN Answers a ON q.id = a.questionId
      LEFT JOIN fulldata f ON q.productId = f.id
    `;

    const queryParams = [];
    if (productId) {
      query += ' WHERE q.productId = ?';
      queryParams.push(productId);
    }

    query += ' ORDER BY q.createdAt DESC, a.createdAt ASC';

    const [results] = await pool.query(query, queryParams);

    // Group questions and answers (same as before)
    const groupedResults = results.reduce((acc, row) => {
      const questionIndex = acc.findIndex((q) => q.id === row.id);
      const answer = row.answerId
        ? {
            id: row.answerId,
            answerText: row.answerText,
            userEmail: row.answerUserEmail,
            createdAt: row.answerCreatedAt,
          }
        : null;

      if (questionIndex === -1) {
        acc.push({
          id: row.id,
          questionText: row.questionText,
          userEmail: row.userEmail,
          createdAt: row.createdAt,
          partnumber: row.partnumber,
          Description: row.Description,
          answers: answer ? [answer] : [],
        });
      } else {
        if (answer) {
          acc[questionIndex].answers.push(answer);
        }
      }
      return acc;
    }, []);

    res.json(groupedResults);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/questions/star', async (req, res) => {
  const { questionId } = req.body;

  try {
    await pool.query('UPDATE questions SET starred = TRUE WHERE id = ?', [questionId]);
    res.status(200).json({ message: 'Question starred successfully' });
  } catch (error) {
    console.error('Error starring question:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/questions/unstar', async (req, res) => {
  const { questionId } = req.body;

  try {
    await pool.query('UPDATE questions SET starred = FALSE WHERE id = ?', [questionId]);
    res.status(200).json({ message: 'Question unstarred successfully' });
  } catch (error) {
    console.error('Error unstarring question:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add a new question
app.post('/api/questions', async (req, res) => {
  const { productId, questionText, userEmail } = req.body;

  try {
    const query = 'INSERT INTO Questions (productId, questionText, userEmail) VALUES (?, ?, ?)';
    const [result] = await pool.query(query, [productId, questionText, userEmail]);

    res.status(201).json({ id: result.insertId, productId, questionText, userEmail, createdAt: new Date() });
  } catch (error) {
    console.error('Error adding question:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/questions/:productId', async (req, res) => {
  const { productId } = req.params;

  try {
    const query = `
      SELECT q.id, q.questionText, q.userEmail, q.createdAt,
             a.id AS answerId, a.answerText, a.userEmail AS answerUserEmail, a.createdAt AS answerCreatedAt,
             p.partnumber, p.Description
      FROM Questions q
      LEFT JOIN Answers a ON q.id = a.questionId
      LEFT JOIN fulldata p ON q.productId = p.id
      WHERE q.productId = ?
      ORDER BY q.createdAt DESC, a.createdAt ASC;
    `;
    const [results] = await pool.query(query, [productId]);

    // Group answers with their respective questions
    const groupedResults = results.reduce((acc, row) => {
      const questionIndex = acc.findIndex((q) => q.id === row.id);
      const answer = row.answerId
        ? {
            id: row.answerId,
            answerText: row.answerText,
            userEmail: row.answerUserEmail,
            createdAt: row.answerCreatedAt,
          }
        : null;

      if (questionIndex === -1) {
        acc.push({
          id: row.id,
          questionText: row.questionText,
          userEmail: row.userEmail,
          createdAt: row.createdAt,
          partNumber: row.partNumber, // Add part number
          description: row.description, // Add description
          answers: answer ? [answer] : [],
        });
      } else {
        if (answer) {
          acc[questionIndex].answers.push(answer);
        }
      }
      return acc;
    }, []);

    res.json(groupedResults);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/api/questions/starred', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM questions WHERE starred = TRUE');
    res.json(results);
  } catch (error) {
    console.error('Error fetching starred questions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add an answer to a question
app.post('/api/questions/answer', async (req, res) => {
  const { questionId, answerText, userEmail } = req.body;

  try {
    const query = 'INSERT INTO Answers (questionId, answerText, userEmail) VALUES (?, ?, ?)';
    const [result] = await pool.query(query, [questionId, answerText, userEmail]);

    res.status(201).json({ id: result.insertId, questionId, answerText, userEmail, createdAt: new Date() });
  } catch (error) {
    console.error('Error adding answer:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// In your Express server file
app.get('/api/relatedproducts/:productId', async (req, res) => {
  const { productId } = req.params;

  try {
    // Fetch the category of the current product
    const [currentProduct] = await pool.query('SELECT mainCategory, subCategory FROM fulldata WHERE id = ?', [productId]);
    if (currentProduct.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    const { mainCategory, subCategory } = currentProduct[0];
    
    // Fetch related products based on the mainCategory or subCategory
    const [relatedProducts] = await pool.query(
      `SELECT id, partnumber, Description, Price, image 
       FROM fulldata 
       WHERE id != ? AND (mainCategory = ? OR subCategory = ?)`,
      [productId, mainCategory, subCategory]
    );
    
    res.json(relatedProducts);
  } catch (error) {
    console.error('Error fetching related products:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// In your Express app
app.get('/api/reviews/:productId', async (req, res) => {
  const { productId } = req.params;

  try {
    const query = 'SELECT * FROM Reviews WHERE productId = ?';
    const [reviews] = await pool.query(query, [productId]);

    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/reviews', async (req, res) => {
  const { productId, userEmail, rating, reviewText } = req.body;

  try {
    const query = 'INSERT INTO Reviews (productId, userEmail, rating, reviewText) VALUES (?, ?, ?, ?)';
    const [result] = await pool.query(query, [productId, userEmail, rating, reviewText]);

    res.status(201).json({ id: result.insertId, productId, userEmail, rating, reviewText });
  } catch (error) {
    console.error('Error adding review:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Assuming you're using Express and have a database connection setup
app.get('/api/product/:id', async (req, res) => {
  const productId = parseInt(req.params.id, 10); // Convert to integer if it's a numeric ID

  if (isNaN(productId)) {
    return res.status(400).json({ message: 'Invalid product ID' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT f.*, pd.description
       FROM fulldata f
       LEFT JOIN product_descriptions pd ON f.id = pd.product_id
       WHERE f.id = ?`,
      [productId]
    );
    
    if (rows.length > 0) {
      res.json(rows[0]); // Return the first product if found
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product details:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.get('/api/spec/product/:id', async (req, res) => {
  const productId = parseInt(req.params.id, 10); // Convert to integer if it's a numeric ID

  if (isNaN(productId)) {
    return res.status(400).json({ message: 'Invalid product ID' });
  }

  try {
    const [productDetails] = await pool.query(
      `SELECT spec_key, spec_value
       FROM product_specifications
       WHERE product_id = ?`,
      [productId]
    );

    if (productDetails.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const [specifications] = await pool.query(
      `SELECT spec_key, spec_value
       FROM product_specifications
       WHERE product_id = ?`,
      [productId]
    );

    res.json({
      ...productDetails[0],
      specifications
    });
  } catch (error) {
    console.error('Error fetching product details:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.post("/api/cart", async (req, res) => {
  const { userEmail, orderId } = req.body;

  if (!userEmail || !orderId) {
    return res
      .status(400)
      .json({ error: "User email and order ID are required" });
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
        const [orderResult] = await pool.query(
          "SELECT ordernumber FROM placing_orders WHERE email = ? AND id = ?",
          [email, notification.id] // Adjust if you have a way to map notification id to order id
        );

        return {
          ...notification,
          ordernumber: orderResult.length ? orderResult[0].ordernumber : "", // Set to an empty string if not found
        };
      })
    );

    res.status(200).json(notificationsWithOrderNumber);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});
app.patch("/api/user/notifications/:notificationId/read", async (req, res) => {
  const notificationId = req.params.notificationId;

  try {
    // Update the read status of the notification
    const [result] = await pool.query(
      "UPDATE usernotifications SET `read` = 1 WHERE id = ?",
      [notificationId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({ message: "Notification marked as read" });
  } catch (error) {
    console.error("Error updating notification status:", error);
    res.status(500).json({ error: "Error updating notification status" });
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

const saltRounds = 10;

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
  const adminEmail = req.user?.email || "unknown"; // Get admin email from request (adjust as needed)

  try {
    // Check if email already exists
    const checkEmailQuery =
      "SELECT email FROM registration WHERE LOWER(email) = LOWER(?)";
    const [result] = await pool.query(checkEmailQuery, [normalizedEmail]);

    if (result.length > 0) {
      console.error("Email already exists:", normalizedEmail);
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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
      hashedPassword, // Store the hashed password
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
    const auditLogQuery = `
      INSERT INTO audit_logs (email, action, success, ip_address, timestamp) 
      VALUES (?, ?, ?, ?, NOW())
    `;
    const action = `Registered new user: ${normalizedEmail}`;
    const success = 1; // Success
    const ipAddress = req.ip || "unknown"; // Adjust as needed

    await pool.query(auditLogQuery, [email, action, success, ipAddress]);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Server error:", err);

    // Insert audit log for failed registration
    const auditLogQuery = `
      INSERT INTO audit_logs (email, action, success, ip_address, timestamp) 
      VALUES (?, ?, ?, ?, NOW())
    `;
    const action = `Failed to register new user: ${normalizedEmail}`;
    const success = 0; // Failure
    const ipAddress = req.ip || "unknown"; // Adjust as needed

    await pool.query(auditLogQuery, [email, action, success, ipAddress]);

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

app.post('/login', async (req, res) => {
  const sql = "SELECT * FROM registration WHERE email = ?";
  const email = req.body.email;
  const password = req.body.password;

  console.log('Login attempt with email:', email);

  try {
    // Query to get user details
    const [users] = await pool.query(sql, [email]);

    if (users.length > 0) {
      const user = users[0];

      // Check if the user is suspended
      if (user.is_suspended) {
        return res.status(403).json({ message: "Account suspended" });
      }

      // Compare the provided password with the hashed password stored in the database
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        const isAdmin = user.role === "superadmin";
        const isMiniAdmin = user.role === "admin";
        const isWarehouse = user.role === "warehouse";
        const isFinance = user.role === "finance";
        // Create JWT token
        const token = jwt.sign(
          { 
            email: user.email, 
            isAdmin: isAdmin, 
            isMiniAdmin: isMiniAdmin,
            isWarehouse: isWarehouse, 
            isFinance: isFinance,
            country: user.country,
          }, 
          secretKey, 
          { expiresIn: "7d" }
        );

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
          isFinance:isFinance,
          country: user.country // Include country in the response
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
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  // Check if email and newPassword are provided
  if (!email || !newPassword) {
    return res.status(400).json({ message: 'Email and new password are required' });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    // Example using SQL, modify accordingly for other databases (e.g., MongoDB)
    const result = await pool.query(
      'UPDATE registration SET password = ? WHERE email = ?',
      [hashedPassword, email]
    );

    // Check if any rows were updated
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Successfully updated
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'An error occurred while resetting the password' });
  }
});




app.post('/api/admin/suspend', async (req, res) => {
  const { adminId, suspend } = req.body;

  if (typeof suspend !== 'boolean') {
    return res.status(400).json({ message: 'Invalid suspension status' });
  }

  try {
    const sql = 'UPDATE registration SET is_suspended = ? WHERE id = ?';
    await pool.query(sql, [suspend, adminId]);

    return res.json({ message: 'Admin status updated successfully' });
  } catch (error) {
    console.error('Error updating admin status:', error);
    return res.status(500).json({ message: 'Failed to update admin status' });
  }
});
app.post('/api/suspenduser', async (req, res) => {
  const { email, userId } = req.body;

  try {
    // Validate admin permissions
    if (email !== 'superadmin@gmail.com') {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    

    // Suspend the user in the database
    await suspendUserById(userId);

    res.status(200).json({ message: 'User suspended successfully' });
  } catch (error) {
    console.error('Error suspending user:', error);
    res.status(500).json({ message: 'Failed to suspend user' });
  }
});



function logAudit({ email, action, success }) {
  const sql = `
    INSERT INTO audit_logs (email, action, success, timestamp) 
    VALUES (?, ?, ?, NOW())
  `;
  pool.query(sql, [email, action, success]).catch((err) => {
    console.error("Error logging audit:", err);
  });
}

app.post("/verifyToken", (req, res) => {
  const token = req.body.token;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

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

// Add this route to your Express app
app.put("/api/clearedorders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  const userEmail = req.body.userEmail; // Assuming you're passing the user's email in the request body

  if (!orderId || !userEmail) {
    return res.status(400).json({ error: "Order ID and user email are required" });
  }

  try {
    // Fetch the admin's permissions
    const adminPermissions = await getAdminPermissions(userEmail);

    if (!adminPermissions.manage_clearorder_permission) {
      return res.status(403).json({ error: "You do not have permission to clear orders" });
    }

    // Update the order status to 'Cleared'
    const [result] = await pool.query(
      `UPDATE placing_orders
       SET status = 'Cleared'
       WHERE id = ?`,
      [orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.status(200).json({ message: "Order cleared successfully" });
  } catch (error) {
    console.error("Error updating order status:", error);
    res.status(500).json({ error: "Error updating order status" });
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
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let orderCountQuery = "SELECT COUNT(*) AS count FROM placing_orders";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      orderCountQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    // Fetch the current order count
    const [currentRows] = await pool.query(orderCountQuery, queryParams);
    const currentCount = currentRows[0].count;

    // Declare previousOrderCountQuery as a let variable
    let previousOrderCountQuery = `
      SELECT COUNT(*) AS count
      FROM placing_orders
      WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    `;

    // Adjust the query for non-superadmin users
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      previousOrderCountQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    const [previousRows] = await pool.query(previousOrderCountQuery, queryParams);
    const previousCount = previousRows[0].count;

    // Calculate the percentage increase
    const percentageIncrease =
      previousCount > 0
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
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let userCountQuery = "SELECT COUNT(*) AS count FROM registration";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
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

app.get("/api/admin/orders/recent", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

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
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
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
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

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

    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
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
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

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

    // Define the base query for fetching pending orders
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

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Add date filtering
    if (startDate) {
      getOrdersQuery += " AND placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate));
    }

    if (endDate) {
      getOrdersQuery += " AND placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate));
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    // Ensure that items are parsed correctly
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

app.get("/api/admin/orders/approved", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

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

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             JSON_ARRAYAGG(
               JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)
             ) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'approved'
    `;

    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Add date filtering
    if (startDate) {
      getOrdersQuery += " AND placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate));
    }

    if (endDate) {
      getOrdersQuery += " AND placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate));
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No pending orders found" });
    }

    // Ensure that items are parsed correctly
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


app.get("/api/admin/orders/cancelled", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Debugging: Log admin details
    console.log(
      `Admin Email: ${adminEmail}, Country: ${adminCountryCode}, Role: ${adminRole}`
    );

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
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
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
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;
  const selectedCountry = req.query.country;

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

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             JSON_ARRAYAGG(
               JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)
             ) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
    `;

    let queryParams = [];

    // Filter by country based on the admin's role and selected country
    if (adminRole === "superadmin") {
      if (selectedCountry) {
        getOrdersQuery += " WHERE placing_orders.country = ?";
        queryParams.push(selectedCountry);
      }
    } else if (adminRole === "admin" || adminRole === "warehouse") {
      if (selectedCountry) {
        getOrdersQuery += " WHERE placing_orders.country = ?";
        queryParams.push(selectedCountry);
      } else {
        getOrdersQuery += " WHERE placing_orders.country = ?";
        queryParams.push(adminCountryCode);
      }
    }

    // Add date filtering
    if (startDate) {
      getOrdersQuery += queryParams.length ? " AND" : " WHERE";
      getOrdersQuery += " placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate).toISOString());
    }

    if (endDate) {
      getOrdersQuery += queryParams.length ? " AND" : " WHERE";
      getOrdersQuery += " placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate).toISOString());
    }

    // Group the results by order ID
    getOrdersQuery += " GROUP BY placing_orders.id";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

  
    // Ensure that items are parsed correctly
    const formattedOrders = orders.map((order) => {
      // If items is already an array, no need to parse
      let parsedItems;
      try {
        parsedItems = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;
      } catch (error) {
        console.error("Error parsing items:", error);
        parsedItems = [];
      }

      return {
        ...order,
        items: parsedItems,
        orderNumber: order.ordernumber,
      };
    });

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});




app.get("/api/admin/orders/country-counts", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;
  const selectedCountry = req.query.country;
  const timePeriod = req.query.timePeriod; // new parameter for time period
  const filterType = req.query.filterType; // new parameter for filter type

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching order counts by country
    let getOrderCountsByCountryQuery = `
      SELECT placing_orders.country, COUNT(*) as orderCount
      FROM placing_orders
    `;

    let queryParams = [];

    // Filter by country based on the admin's role and selected country
    if (adminRole === "superadmin") {
      // Superadmins can see orders from any country
      if (selectedCountry) {
        getOrderCountsByCountryQuery += " WHERE placing_orders.country = ?";
        queryParams.push(selectedCountry);
      }
    } else if (adminRole === "admin" || adminRole === "warehouse") {
      // Admins and warehouse admins see orders only for their assigned country
      if (selectedCountry) {
        getOrderCountsByCountryQuery += " WHERE placing_orders.country = ?";
        queryParams.push(selectedCountry);
      } else {
        getOrderCountsByCountryQuery += " WHERE placing_orders.country = ?";
        queryParams.push(adminCountryCode);
      }
    }

    // Add filtering based on the selected filter type and time period
    if (filterType === "custom" && startDate && endDate) {
      getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
      getOrderCountsByCountryQuery +=
        " placing_orders.created_at >= ? AND placing_orders.created_at <= ?";
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      const endOfMonth = new Date();
      const startOfMonth = new Date();
      startOfMonth.setMonth(endOfMonth.getMonth() - 3);
      startOfMonth.setDate(1);
      getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
      getOrderCountsByCountryQuery +=
        " placing_orders.created_at >= ? AND placing_orders.created_at <= ?";
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      const endOfWeek = new Date();
      const startOfWeek = new Date();
      startOfWeek.setDate(endOfWeek.getDate() - 21); // Last 3 weeks
      getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
      getOrderCountsByCountryQuery +=
        " placing_orders.created_at >= ? AND placing_orders.created_at <= ?";
      queryParams.push(startOfWeek, endOfWeek);
    } else {
      // Handle custom time period filtering
      if (timePeriod === "weekly") {
        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
        getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
        getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
        queryParams.push(startOfWeek.toISOString());
      } else if (timePeriod === "monthly") {
        const startOfMonth = new Date();
        startOfMonth.setDate(1);
        getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
        getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
        queryParams.push(startOfMonth.toISOString());
      } else {
        if (startDate) {
          getOrderCountsByCountryQuery += queryParams.length
            ? " AND"
            : " WHERE";
          getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
          queryParams.push(new Date(startDate).toISOString());
        }

        if (endDate) {
          getOrderCountsByCountryQuery += queryParams.length
            ? " AND"
            : " WHERE";
          getOrderCountsByCountryQuery += " placing_orders.created_at <= ?";
          queryParams.push(new Date(endDate).toISOString());
        }
      }
    }

    // Group the results by country
    getOrderCountsByCountryQuery += " GROUP BY placing_orders.country";

    const [orderCountsByCountry] = await pool.query(
      getOrderCountsByCountryQuery,
      queryParams
    );

    if (orderCountsByCountry.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orderCountsByCountry);
  } catch (error) {
    console.error("Error fetching order counts by country:", error);
    res.status(500).json({ error: "Error fetching order counts by country" });
  }
});

app.get("/api/admin/orders/city-counts", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;
  const selectedCountry = req.query.country;
  const timePeriod = req.query.timePeriod; // new parameter for time period

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching order counts by country
    let getOrderCountsByCountryQuery = `
      SELECT placing_orders.country, COUNT(*) as orderCount
      FROM placing_orders
    `;

    let queryParams = [];

    // Filter by country based on the admin's role and selected country
    if (adminRole === "superadmin") {
      // Superadmins can see orders from any country
      if (selectedCountry) {
        getOrderCountsByCountryQuery += " WHERE placing_orders.country = ?";
        queryParams.push(selectedCountry);
      }
    } else if (adminRole === "admin" || adminRole === "warehouse") {
      // Admins and warehouse admins see orders only for their assigned country
      if (selectedCountry) {
        getOrderCountsByCountryQuery += " WHERE placing_orders.city = ?";
        queryParams.push(selectedCountry);
      } else {
        getOrderCountsByCountryQuery += " WHERE placing_orders.city = ?";
        queryParams.push(adminCountryCode);
      }
    }

    // Add date filtering based on the selected time period
    if (timePeriod === "weekly") {
      const startOfWeek = new Date();
      startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
      getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
      getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
      queryParams.push(startOfWeek.toISOString());
    } else if (timePeriod === "monthly") {
      const startOfMonth = new Date();
      startOfMonth.setDate(1);
      getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
      getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
      queryParams.push(startOfMonth.toISOString());
    } else {
      // Handle custom date range if provided
      if (startDate) {
        getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
        getOrderCountsByCountryQuery += " placing_orders.created_at >= ?";
        queryParams.push(new Date(startDate).toISOString());
      }

      if (endDate) {
        getOrderCountsByCountryQuery += queryParams.length ? " AND" : " WHERE";
        getOrderCountsByCountryQuery += " placing_orders.created_at <= ?";
        queryParams.push(new Date(endDate).toISOString());
      }
    }

    // Group the results by country
    getOrderCountsByCountryQuery += " GROUP BY placing_orders.country";

    const [orderCountsByCountry] = await pool.query(
      getOrderCountsByCountryQuery,
      queryParams
    );

    if (orderCountsByCountry.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orderCountsByCountry);
  } catch (error) {
    console.error("Error fetching order counts by country:", error);
    res.status(500).json({ error: "Error fetching order counts by country" });
  }
});
app.get("/api/admin/orders/sales-by-country", async (req, res) => {
  const adminEmail = req.query.email;
  const filterType = req.query.filterType;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT country, SUM(totalprice) as total_sales
      FROM placing_orders
    `;

    let queryParams = [];

    if (filterType === "custom" && startDate && endDate) {
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      // Filter by the last 3 months
      const endOfMonth = new Date();
      const startOfMonth = new Date();
      startOfMonth.setMonth(endOfMonth.getMonth() - 3);
      startOfMonth.setDate(1);
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      // Filter by the last 3 weeks
      const endOfWeek = new Date();
      const startOfWeek = new Date();
      startOfWeek.setDate(endOfWeek.getDate() - 21); // Last 3 weeks
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfWeek, endOfWeek);
    }

    // Filter by country based on the admin's role
    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by country and sum total sales
    getOrdersQuery += " GROUP BY country ORDER BY country";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});
app.get("/api/admin/orders/sales-by-city", async (req, res) => {
  const adminEmail = req.query.email;
  const filterType = req.query.filterType;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's role and (optionally) city from the registration table
    const adminQuery =
      "SELECT country, city, role FROM registration WHERE email = ?";
    const [adminResult] = await pool.query(adminQuery, [adminEmail]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const {
      country: adminCountryCode,
      city: adminCity,
      role: adminRole,
    } = adminResult[0];

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT city, SUM(totalprice) as total_sales
      FROM placing_orders
    `;

    let queryParams = [];

    if (filterType === "custom" && startDate && endDate) {
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      // Filter by the last 3 months
      const endOfMonth = new Date();
      const startOfMonth = new Date();
      startOfMonth.setMonth(endOfMonth.getMonth() - 3);
      startOfMonth.setDate(1);
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      // Filter by the last 3 weeks
      const endOfWeek = new Date();
      const startOfWeek = new Date();
      startOfWeek.setDate(endOfWeek.getDate() - 21); // Last 3 weeks
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfWeek, endOfWeek);
    } else {
      // If no valid filter type, return an error
      return res.status(400).json({ error: "Invalid filterType provided" });
    }

    // Filter by city based on the admin's role
    if (adminRole !== "superadmin") {
      if (adminRole === "cityadmin" && adminCity) {
        getOrdersQuery += " AND city = ?";
        queryParams.push(adminCity);
      } else if (adminRole === "countryadmin") {
        getOrdersQuery += " AND country = ?";
        queryParams.push(adminCountryCode);
      }
    }

    // Group the results by city and sum total sales
    getOrdersQuery += " GROUP BY city ORDER BY city";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});

app.get("/api/admin/orders/orders-by-country", async (req, res) => {
  const adminEmail = req.query.email;
  const filterType = req.query.filterType;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT country, SUM(ordernumber) as total_orders
      FROM placing_orders
    `;

    let queryParams = [];

    if (filterType === "custom" && startDate && endDate) {
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      // Filter by the last 3 months
      const endOfMonth = new Date();
      const startOfMonth = new Date();
      startOfMonth.setMonth(endOfMonth.getMonth() - 3);
      startOfMonth.setDate(1);
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      // Filter by the last 3 weeks
      const endOfWeek = new Date();
      const startOfWeek = new Date();
      startOfWeek.setDate(endOfWeek.getDate() - 21); // Last 3 weeks
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfWeek, endOfWeek);
    }

    // Filter by country based on the admin's role
    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by country and sum total sales
    getOrdersQuery += " GROUP BY country ORDER BY country";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});
app.get("/api/admin/orders/orders-by-city", async (req, res) => {
  const adminEmail = req.query.email;
  const filterType = req.query.filterType;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's role and (optionally) city from the registration table
    const adminQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminResult] = await pool.query(adminQuery, [adminEmail]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const {
      country: adminCountryCode,
      city: adminCity,
      role: adminRole,
    } = adminResult[0];

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT city, COUNT(*) AS total_orders
      FROM placing_orders
    `;

    let queryParams = [];

    // Add conditions for date filtering
    let conditions = [];

    if (filterType === "custom" && startDate && endDate) {
      conditions.push("created_at >= ? AND created_at <= ?");
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      const endOfMonth = new Date();
      const startOfMonth = new Date();
      startOfMonth.setMonth(endOfMonth.getMonth() - 3);
      startOfMonth.setDate(1);
      conditions.push("created_at >= ? AND created_at <= ?");
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      const endOfWeek = new Date();
      const startOfWeek = new Date();
      startOfWeek.setDate(endOfWeek.getDate() - 21); // Last 3 weeks
      conditions.push("created_at >= ? AND created_at <= ?");
      queryParams.push(startOfWeek, endOfWeek);
    } else {
      return res.status(400).json({ error: "Invalid filterType provided" });
    }

    // Add conditions for city or country filtering based on admin role
    if (adminRole !== "superadmin") {
      if (adminRole === "cityadmin" && adminCity) {
        conditions.push("city = ?");
        queryParams.push(adminCity);
      } else if (adminRole === "countryadmin") {
        conditions.push("country = ?");
        queryParams.push(adminCountryCode);
      }
    }

    // Join all conditions with "AND" and append them to the query
    if (conditions.length > 0) {
      getOrdersQuery += " WHERE " + conditions.join(" AND ");
    }

    // Group the results by city and order by city name
    getOrdersQuery += " GROUP BY city ORDER BY city";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});



app.get("/api/admin/orders/company-orders-count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's role from the registration table
    const roleQuery = "SELECT role FROM registration WHERE email = ?";
    const [roleResult] = await pool.query(roleQuery, [adminEmail]);

    if (roleResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { role: adminRole } = roleResult[0];

    // Define the query to count orders and sum sales by company name
    let getCompanyOrdersCountQuery = `
      SELECT company_name, SUM(totalprice) as total_sales, COUNT(*) as order_count
      FROM placing_orders
    `;

    let queryParams = [];

    // If the admin is not a superadmin, restrict to their country
    if (adminRole !== "superadmin") {
      const countryQuery = "SELECT country FROM registration WHERE email = ?";
      const [countryResult] = await pool.query(countryQuery, [adminEmail]);

      if (countryResult.length === 0) {
        return res.status(404).json({ error: "Country not found for admin" });
      }

      const { country: adminCountry } = countryResult[0];

      getCompanyOrdersCountQuery += " WHERE placing_orders.country = ?";
      queryParams.push(adminCountry);
    }

    // Complete the query
    getCompanyOrdersCountQuery +=
      " GROUP BY company_name ORDER BY order_count DESC";

    const [companyOrdersCount] = await pool.query(
      getCompanyOrdersCountQuery,
      queryParams
    );

    if (companyOrdersCount.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(companyOrdersCount);
  } catch (error) {
    console.error("Error fetching company orders count:", error);
    res.status(500).json({ error: "Error fetching company orders count" });
  }
});
app.get("/api/admin/orders/company-orders-count-chart", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's role from the registration table
    const roleQuery = "SELECT role FROM registration WHERE email = ?";
    const [roleResult] = await pool.query(roleQuery, [adminEmail]);

    if (roleResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { role: adminRole } = roleResult[0];

    // Define the query to count orders and sum sales by company name, year, and month
    let getCompanyOrdersCountQuery = `
      SELECT company_name,
             YEAR(created_at) AS year,
             MONTH(created_at) AS month,
             SUM(totalprice) AS total_sales,
             COUNT(*) AS order_count
      FROM placing_orders
      WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 4 MONTH)
    `;

    let queryParams = [];

    // If the admin is not a superadmin, restrict to their country
    if (adminRole !== "superadmin") {
      const countryQuery = "SELECT country FROM registration WHERE email = ?";
      const [countryResult] = await pool.query(countryQuery, [adminEmail]);

      if (countryResult.length === 0) {
        return res.status(404).json({ error: "Country not found for admin" });
      }

      const { country: adminCountry } = countryResult[0];

      getCompanyOrdersCountQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountry);
    }

    // Complete the query
    getCompanyOrdersCountQuery += `
      GROUP BY company_name, YEAR(created_at), MONTH(created_at)
      ORDER BY YEAR(created_at) ASC, MONTH(created_at) ASC, company_name ASC
    `;

    const [companyOrdersCount] = await pool.query(
      getCompanyOrdersCountQuery,
      queryParams
    );

    if (companyOrdersCount.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(companyOrdersCount);
  } catch (error) {
    console.error("Error fetching company orders count:", error);
    res.status(500).json({ error: "Error fetching company orders count" });
  }
});

app.get("/api/admin/orders/sales-by-country-comparison", async (req, res) => {
  const adminEmail = req.query.email;
  const filterType = req.query.filterType;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching orders
    let getOrdersQuery = `
      SELECT DATE_FORMAT(created_at, '%Y-%m') as month, country, SUM(totalprice) as total_sales
      FROM placing_orders
    `;

    let queryParams = [];

    if (filterType === "custom" && startDate && endDate) {
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(new Date(startDate), new Date(endDate));
    } else if (filterType === "monthly") {
      // Filter by current month
      const startOfMonth = new Date();
      startOfMonth.setDate(1);
      const endOfMonth = new Date();
      endOfMonth.setMonth(endOfMonth.getMonth() + 1);
      endOfMonth.setDate(0);
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfMonth, endOfMonth);
    } else if (filterType === "weekly") {
      // Filter by current week
      const startOfWeek = new Date();
      startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
      const endOfWeek = new Date();
      endOfWeek.setDate(endOfWeek.getDate() + (6 - endOfWeek.getDay()));
      getOrdersQuery += " WHERE created_at >= ? AND created_at <= ?";
      queryParams.push(startOfWeek, endOfWeek);
    }

    // Filter by country based on the admin's role
    if (adminRole !== "superadmin") {
      getOrdersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by month and country
    getOrdersQuery += " GROUP BY month, country ORDER BY month, country";

    const [orders] = await pool.query(getOrdersQuery, queryParams);

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});

app.get("/api/admin/orders-per-month", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];
    let getOrdersPerMonthQuery = `
      SELECT DATE_FORMAT(placing_orders.created_at, '%Y-%m') as month, COUNT(*) as orderCount
      FROM placing_orders
    `;

    let queryParams = [];

    // Filter by country based on the admin's role
    if (adminRole === "superadmin") {
      // Superadmins can see orders from any country
      // No country filter
    } else if (adminRole === "admin" || adminRole === "warehouse") {
      getOrdersPerMonthQuery += " WHERE placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    getOrdersPerMonthQuery += " GROUP BY month ORDER BY month ASC";

    const [ordersPerMonth] = await pool.query(
      getOrdersPerMonthQuery,
      queryParams
    );

    if (ordersPerMonth.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json(ordersPerMonth);
  } catch (error) {
    console.error("Error fetching orders per month:", error);
    res.status(500).json({ error: "Error fetching orders per month" });
  }
});

app.get("/api/admin/orders/finished_packing", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Finished Packing'
    `;

    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Add date filtering
    if (startDate) {
      getOrdersQuery += " AND placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate));
    }

    if (endDate) {
      getOrdersQuery += " AND placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate));
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

app.get("/api/admin/orders/completed_orders", async (req, res) => {
  const adminEmail = req.query.email;
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching pending orders
    let getOrdersQuery = `
      SELECT placing_orders.*, 
             GROUP_CONCAT(JSON_OBJECT('description', oi.description, 'quantity', oi.quantity, 'price', oi.price)) as items
      FROM placing_orders
      LEFT JOIN order_items oi ON placing_orders.id = oi.order_id
      WHERE placing_orders.status = 'Completed'
    `;

    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getOrdersQuery += " AND placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Add date filtering
    if (startDate) {
      getOrdersQuery += " AND placing_orders.created_at >= ?";
      queryParams.push(new Date(startDate));
    }

    if (endDate) {
      getOrdersQuery += " AND placing_orders.created_at <= ?";
      queryParams.push(new Date(endDate));
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
  const userEmail = req.headers["user-email"]; // Retrieve user email from headers

  try {
    const permissions = await getAdminPermissions(userEmail);

    if (!permissions.create_permission) {
      return res
        .status(403)
        .json({ error: "Permission denied: Cannot create products" });
    }

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
  const products = req.body.products; // Expecting an array of products
  const userEmail = req.headers["user-email"]; // Retrieve user email from headers

 
  if (!Array.isArray(products) || products.length === 0) {
    console.error("Invalid products data: Must be a non-empty array.");
    return res.status(400).json({ error: "Invalid products data: Must be a non-empty array" });
  }

  let connection;

  try {
    // Check admin permissions
    const permissions = await getAdminPermissions(userEmail);
    console.log("Admin permissions for user:", userEmail, permissions);

    if (!permissions) {
      console.error("Admin rights not found for the user:", userEmail);
      return res.status(404).json({ error: "Admin rights not found for the user." });
    }

    if (!permissions.create_permission) {
      console.error("Permission denied: User does not have create permissions.");
      return res.status(403).json({ error: "Permission denied: Cannot create products" });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    for (const product of products) {
      const {
        partnumber = '',
        description = '',
        image = '',
        thumb1 = '',
        thumb2 = '',
        prices = [],
        mainCategory = '',
        subCategory = '',
      } = product;

      

      // Insert product into fulldata table
      const productQuery = `INSERT INTO fulldata (partnumber, description, image, thumb1, thumb2, mainCategory, subCategory) VALUES (?, ?, ?, ?, ?, ?, ?)`;
      const [result] = await connection.query(productQuery, [partnumber, description, image, thumb1, thumb2, mainCategory, subCategory]);
      const productId = result.insertId; // Get the generated id

      // Insert prices into product_prices table
      for (const price of prices) {
        const { country_code, price: priceValue, stock_quantity } = price;
      
        // Ensure stock_quantity is not null or undefined
        const finalStockQuantity = stock_quantity != null ? stock_quantity : 0;
      
        const priceQuery = `INSERT INTO product_prices (product_id, country_code, price, stock_quantity) VALUES (?, ?, ?, ?)`;
        console.log('Inserting price:', { productId, country_code, priceValue, finalStockQuantity });
        await connection.query(priceQuery, [productId, country_code, priceValue, finalStockQuantity]);
      }
      
    }

    await connection.commit();
    console.log("All products added successfully. Transaction committed.");
    res.status(201).json({ message: "Products added successfully" });
  } catch (error) {
    if (connection) {
      await connection.rollback();
    }
    console.error("Error adding products:", error.message);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      connection.release();
    }
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
  const adminEmail = req.query.email; // Get the admin's email from query parameters

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryResult] = await pool.query(countryQuery, [adminEmail]);

    if (countryResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryResult[0];

    // Fetch product details
    const productQuery = `
      SELECT id, partnumber, Description, image, thumb1, thumb2, mainCategory, subCategory, detailedDescription
      FROM fulldata
      WHERE id = ?
    `;
    const [product] = await pool.query(productQuery, [productId]);

    if (product.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    // Fetch product specifications
    const specificationsQuery = `
      SELECT spec_key, spec_value
      FROM product_specifications
      WHERE product_id = ?
    `;
    const [specifications] = await pool.query(specificationsQuery, [productId]);

    // Fetch product prices
    let pricesQuery = `
      SELECT country_code, price, stock_quantity
      FROM product_prices
      WHERE product_id = ?
    `;
    const queryParams = [productId];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin") {
      pricesQuery += " AND country_code = ?";
      queryParams.push(adminCountryCode);
    }

    const [prices] = await pool.query(pricesQuery, queryParams);

    // Fetch product descriptions
    const descriptionsQuery = `
      SELECT description
      FROM product_descriptions
      WHERE product_id = ?
    `;
    const [descriptions] = await pool.query(descriptionsQuery, [productId]);

    // Combine product details, specifications, descriptions, and filtered prices
    res.json({
      ...product[0],
      specifications,
      descriptions: descriptions.map(desc => desc.description),
      prices
    });
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
    descriptions = [], // Default to an empty array if not provided
    specifications = [], // Default to an empty array if not provided
    image,
    thumb1,
    thumb2,
    mainCategory,
    subCategory,
    prices = [], // Default to an empty array if not provided
    email,
  } = req.body;

  console.log(`Received PUT request for product ID: ${productId}`);

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Log the attempted update action
    const details = `Attempted to update product: partnumber=${partnumber}, Description=${Description}, image=${image}, thumb1=${thumb1}, thumb2=${thumb2}, mainCategory=${mainCategory}, subCategory=${subCategory}, prices=${JSON.stringify(
      prices
    )}`;
    const auditLogQueryAttempt = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'attempted_update', ?, ?)
    `;
    await connection.query(auditLogQueryAttempt, [productId, details, email]);

    // Check admin permissions before proceeding
    const adminPermissions = await getAdminPermissions(email);
    console.log("Admin permissions:", adminPermissions);

    if (!adminPermissions || !adminPermissions.update_permission) {
      const deniedDetails = `Permission denied for user: ${email}`;
      const auditLogQueryDenied = `
        INSERT INTO product_audit_log (product_id, action, details, changed_by)
        VALUES (?, 'update_failed', ?, ?)
      `;
      await connection.query(auditLogQueryDenied, [
        productId,
        deniedDetails,
        email,
      ]);

      throw new Error("Permission denied");
    }

    // Update product details in the fulldata table
    const updateProductQuery = `
      UPDATE fulldata
      SET partnumber = ?, Description = ?, image = ?, thumb1 = ?, thumb2 = ?, mainCategory = ?, subCategory = ?
      WHERE id = ?
    `;
    await connection.query(updateProductQuery, [
      partnumber,
      Description,
      image,
      thumb1,
      thumb2,
      mainCategory,
      subCategory,
      productId,
    ]);

    // Update descriptions in the product_descriptions table
    if (Array.isArray(descriptions)) {
      // Delete existing descriptions for the product
      const deleteDescriptionsQuery = `DELETE FROM product_descriptions WHERE product_id = ?`;
      await connection.query(deleteDescriptionsQuery, [productId]);

      // Insert new descriptions
      const insertDescriptionQuery = `
        INSERT INTO product_descriptions (product_id, description)
        VALUES (?, ?)
      `;
      for (const desc of descriptions) {
        await connection.query(insertDescriptionQuery, [productId, desc]);
      }
    } else {
      console.warn("Descriptions provided is not an array. Skipping description update.");
    }

    // Update specifications in the product_specifications table
    if (Array.isArray(specifications)) {
      // Delete existing specifications for the product
      const deleteSpecificationsQuery = `DELETE FROM product_specifications WHERE product_id = ?`;
      await connection.query(deleteSpecificationsQuery, [productId]);

      // Insert new specifications
      const insertSpecificationQuery = `
        INSERT INTO product_specifications (product_id, spec_key, spec_value)
        VALUES (?, ?, ?)
      `;
      for (const spec of specifications) {
        await connection.query(insertSpecificationQuery, [
          productId,
          spec.spec_key,
          spec.spec_value,
        ]);
      }
    } else {
      console.warn("Specifications provided is not an array. Skipping specifications update.");
    }

    // Update prices in the product_prices table
    if (Array.isArray(prices)) {
      // Delete existing prices for the product
      const deletePricesQuery = `DELETE FROM product_prices WHERE product_id = ?`;
      await connection.query(deletePricesQuery, [productId]);

      // Insert or update prices and stock quantities
      const insertOrUpdatePricesQuery = `
        INSERT INTO product_prices (product_id, country_code, price, stock_quantity)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE price = VALUES(price), stock_quantity = VALUES(stock_quantity);
      `;
      for (const price of prices) {
        await connection.query(insertOrUpdatePricesQuery, [
          productId,
          price.country_code,
          price.price,
          price.stock_quantity,
        ]);
      }
    } else {
      console.warn("Prices provided is not an array. Skipping price update.");
    }

    // Log the successful update action
    const successDetails = `Successfully updated product details: partnumber=${partnumber}, Description=${Description}, image=${image}, thumb1=${thumb1}, thumb2=${thumb2}, mainCategory=${mainCategory}, subCategory=${subCategory}, prices=${JSON.stringify(
      prices
    )}`;
    const auditLogQuerySuccess = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'update_successful', ?, ?)
    `;
    await connection.query(auditLogQuerySuccess, [
      productId,
      successDetails,
      email,
    ]);

    await connection.commit();
    res.json({ message: "Product updated successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});



app.delete("/api/viewproducts/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10); // Ensure productId is an integer
  const { email } = req.body; // Extract email from request body

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Log the attempted delete action
    const attemptDetails = `Attempted to delete product with ID: ${productId}`;
    const auditLogAttemptQuery = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'attempted_delete', ?, ?)
    `;
    await connection.query(auditLogAttemptQuery, [
      productId,
      attemptDetails,
      email,
    ]);

    // Check admin permissions before proceeding
    const adminPermissions = await getAdminPermissions(email);
    console.log("Admin permissions:", adminPermissions); // Debug permission retrieval

    if (!adminPermissions || !adminPermissions.delete_permission) {
      // Log the failed attempt due to permission denial
      const deniedDetails = `Permission denied for user: ${email}`;
      const auditLogDeniedQuery = `
        INSERT INTO product_audit_log (product_id, action, details, changed_by)
        VALUES (?, 'delete_failed', ?, ?)
      `;
      await connection.query(auditLogDeniedQuery, [
        productId,
        deniedDetails,
        email,
      ]);

      throw new Error("Permission denied");
    }

    // Delete from product_prices table
    await connection.query("DELETE FROM product_prices WHERE product_id = ?", [
      productId,
    ]);

    // Delete from fulldata table
    await connection.query("DELETE FROM fulldata WHERE id = ?", [productId]);

    // Log the successful delete action
    const successDetails = `Successfully deleted product with ID: ${productId}`;
    const auditLogSuccessQuery = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'delete_successful', ?, ?)
    `;
    await connection.query(auditLogSuccessQuery, [
      productId,
      successDetails,
      email,
    ]);

    await connection.commit();
    res.json({ message: "Product deleted successfully" });

    // Notify admin
    const notificationLogQuery = `
      INSERT INTO notifications (user_email, message, date)
      VALUES (?, ?, NOW())
    `;
    await connection.query(notificationLogQuery, [
      email,
      `Product ${productId} deleted`,
    ]);
  } catch (error) {
    await connection.rollback();
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product" });
  } finally {
    connection.release();
  }
});

app.get("/api/admin/products/near-completion", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching products
    let getProductsQuery = `
      SELECT f.partnumber, f.description, pp.price, pp.stock_quantity, pp.country_code
      FROM fulldata f
      JOIN product_prices pp ON f.id = pp.product_id
      WHERE pp.stock_quantity <= 12
    `;

    if (adminRole !== "superadmin") {
      getProductsQuery += " AND pp.country_code = ?";
    }

    const [products] = await pool.query(
      getProductsQuery,
      adminRole !== "superadmin" ? [adminCountryCode] : []
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

app.get("/api/admin/notifications", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const adminDetailsQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [adminDetailsResult] = await pool.query(adminDetailsQuery, [
      adminEmail,
    ]);

    if (adminDetailsResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } =
      adminDetailsResult[0];

    // Define the base query for fetching notifications
    let getNotificationsQuery = `
      SELECT * 
      FROM notifications
    `;

    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getNotificationsQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    // Order notifications by creation date
    getNotificationsQuery += " ORDER BY created_at DESC";

    const [notifications] = await pool.query(
      getNotificationsQuery,
      queryParams
    );

    if (notifications.length === 0) {
      return res.status(404).json({ message: "No notifications found" });
    }

    // Formatting notifications if needed (e.g., parsing JSON fields)
    const formattedNotifications = notifications.map((notification) => ({
      ...notification,
      // Example: If there's a JSON field, parse it
      // data: notification.data ? JSON.parse(notification.data) : null,
    }));

    res.status(200).json(formattedNotifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

// Add this route to your Express server file (e.g., index.js or routes.js)
app.put("/api/admin/notifications/:id/read", async (req, res) => {
  const { id } = req.params;
  const { email } = req.body; // Read email from request body

  const connection = await pool.getConnection();
  try {
    // Fetch the notification to check its country
    const notificationQuery = "SELECT country FROM notifications WHERE id = ?";
    const [notificationResult] = await connection.query(notificationQuery, [
      id,
    ]);

    if (notificationResult.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    const notificationCountry = notificationResult[0].country;

    // Fetch the admin's country and role
    const adminQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminResult] = await connection.query(adminQuery, [email]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    // Check if the notification is relevant to the admin's country or if the admin is a superadmin
    if (adminRole !== "superadmin" && notificationCountry !== adminCountry) {
      return res
        .status(403)
        .json({
          error: "Forbidden: Notification not relevant to your country",
        });
    }

    // Mark the notification as read
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
app.delete("/api/admin/notifications/:id", async (req, res) => {
  const { id } = req.params;
  const { email } = req.body; // Read email from request body

  const connection = await pool.getConnection();
  try {
    // Fetch the notification to check its country
    const notificationQuery = "SELECT country FROM notifications WHERE id = ?";
    const [notificationResult] = await connection.query(notificationQuery, [
      id,
    ]);

    if (notificationResult.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    const notificationCountry = notificationResult[0].country;

    // Fetch the admin's country and role
    const adminQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [adminResult] = await connection.query(adminQuery, [email]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    // Check if the notification is relevant to the admin's country or if the admin is a superadmin
    if (adminRole !== "superadmin" && notificationCountry !== adminCountry) {
      return res
        .status(403)
        .json({
          error: "Forbidden: Notification not relevant to your country",
        });
    }

    // Delete the notification
    await connection.query("DELETE FROM notifications WHERE id = ?", [id]);

    res.json({ message: "Notification deleted" });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({ error: "Error deleting notification" });
  } finally {
    connection.release();
  }
});

app.get("/api/admin/notifications/count", async (req, res) => {
  const adminEmail = req.query.email;
  try {
    if (!adminEmail) {
      return res.status(401).json({ error: "Unauthorized: No email provided" });
    }

    // Fetch the admin's country and role
    const [adminResult] = await pool.query(
      "SELECT country, role FROM registration WHERE email = ?",
      [adminEmail]
    );

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountry, role: adminRole } = adminResult[0];

    // Determine the query based on admin's role
    let countQuery;
    let queryParams = [];

    if (adminRole === "superadmin") {
      // Superadmins receive the count of all unread notifications
      countQuery =
        "SELECT COUNT(*) AS count FROM notifications WHERE status = 'unread'";
    } else {
      // Regular admins receive the count of unread notifications for their country
      countQuery =
        "SELECT COUNT(*) AS count FROM notifications WHERE status = 'unread' AND country = ?";
      queryParams.push(adminCountry);
    }

    // Fetch the count of unread notifications
    const [notificationCountResult] = await pool.query(countQuery, queryParams);

    // Send the count as JSON response
    res.json({ count: notificationCountResult[0].count });
  } catch (error) {
    console.error("Error fetching notifications count:", error);
    res.status(500).json({ error: "Error fetching notifications count" });
  }
});

app.get("/api/admin/users/count", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    let userCountQuery = "SELECT COUNT(*) AS count FROM registration";
    let queryParams = [];

    // If the user is not a superadmin, filter by country
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

const countryMappings = {
  KE: "Kenya",
  UG: "Uganda",
  TZ: "Tanzania",
};

// API endpoint to get the list of countries
app.get("/api/countries", async (req, res) => {
  try {
    // Fetch unique country codes from the registration table
    const query = "SELECT DISTINCT country FROM registration";
    const [results] = await pool.query(query);

    // Map the codes to names using the hardcoded mapping
    const countries = results.map((row) => ({
      code: row.country,
      name: countryMappings[row.country] || "Unknown",
    }));

    res.json(countries);
  } catch (error) {
    console.error("Error fetching countries:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/registeredusers", async (req, res) => {
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

    // Construct the base query and parameters
    let getUsersQuery = "SELECT * FROM registration";
    const queryParams = [];

    // Build the filtering conditions based on the admin role
    if (adminRole !== "superadmin") {
      getUsersQuery += " WHERE country = ?";
      queryParams.push(adminCountryCode);
    }

    // Apply the country filter if specified, modifying the query accordingly
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



// In your Express server file
app.get("/api/newregisteredusers", async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country;
  const daysAgo = 14; // Number of days to filter recent registrations

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Get the date 14 days ago
    const date14DaysAgo = new Date();
    date14DaysAgo.setDate(date14DaysAgo.getDate() - daysAgo);
    const formattedDate = date14DaysAgo.toISOString().split("T")[0]; // Format as YYYY-MM-DD

    let getUsersQuery =
      "SELECT * FROM registration WHERE registration_date >= ?";
    let queryParams = [formattedDate];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin") {
      getUsersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Apply additional country filter if provided
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
app.get("/api/monthlyusergrowth", async (req, res) => {
  const adminEmail = req.query.email;
  const filterCountry = req.query.country;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Base query to get user registration count per month
    let getUsersQuery = `
      SELECT DATE_FORMAT(registration_date, '%Y-%m') AS month, COUNT(*) AS userCount
      FROM registration
      WHERE registration_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
    `;
    let queryParams = [];

    // Filter by country if needed
    if (adminRole !== "superadmin") {
      getUsersQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Apply additional country filter if provided
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

app.get("/api/registeredusers/:id", async (req, res) => {
  try {
    const { email } = req.query; // Assuming email is passed in the query parameters
    const userId = req.params.id;

    // Check if the requesting admin has the right to view users
    const permissions = await getAdminPermissions(email);
    if (!permissions || !permissions.read_permission) {
      return res.status(403).json({ message: "Access denied" });
    }

    // Fetch user details if permissions are valid
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
      `SELECT placing_orders.ordernumber, placing_orders.email, placing_orders.totalprice, placing_orders.Status, placing_orders.created_at, placing_orders.city,
              CONCAT('[', GROUP_CONCAT(
                JSON_OBJECT('id', oi.id, 'description', oi.description, 'quantity', oi.quantity, 'price', oi.price)
                SEPARATOR ','
              ), ']') as items
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
   
    // Check if items is a string and properly enclosed in brackets
    if (typeof order.items === 'string') {
      try {
        // Attempt to parse the JSON string
        order.items = JSON.parse(order.items);
      } catch (parseError) {
        console.error("Error parsing items JSON:", parseError);
        // Default to an empty array if parsing fails
        order.items = [];
      }
    } else {
      order.items = [];
    }

    res.status(200).json(order);
  } catch (error) {
    console.error("Error fetching order details:", error);
    res.status(500).json({ error: "Error fetching order details" });
  }
});



app.patch("/api/admin/orders/:orderId/status", async (req, res) => {
  const orderId = req.params.orderId;
  const { status, userEmail } = req.body; // Ensure this is the logged-in admin's email

  // Validate required fields
  if (!userEmail || !status) {
    return res.status(400).json({ message: "Invalid request data" });
  }

  try {
    // Fetch admin user ID based on the logged-in admin's email
    const [adminResult] = await pool.query(
      "SELECT id FROM registration WHERE email = ?",
      [userEmail]
    );

    if (adminResult.length === 0) {
      return res.status(404).json({ message: "Admin not found" });
    }

    const adminId = adminResult[0].id;

    // Fetch admin permissions based on the admin's user ID
    const [permissionsResult] = await pool.query(
      "SELECT * FROM admin_rights WHERE user_id = ?",
      [adminId]
    );

    if (permissionsResult.length === 0) {
      return res.status(404).json({ message: "Admin permissions not found" });
    }

    const currentAdmin = permissionsResult[0];

    // Check permission to manage orders
    if (!currentAdmin.manage_orders_permission) {
      return res
        .status(403)
        .json({ message: "Forbidden: You do not have permission to manage orders" });
    }

    // Update order status
    const [updateResult] = await pool.query(
      "UPDATE placing_orders SET status = ? WHERE id = ?",
      [status, orderId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Fetch the order number and user email for notification
    const [orderResult] = await pool.query(
      "SELECT email, ordernumber FROM placing_orders WHERE id = ?",
      [orderId]
    );

    if (orderResult.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    const { email: userOrderEmail, ordernumber } = orderResult[0];

    // Insert notification with the order number
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

app.get("/api/admin/mostOrderedProducts", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT partnumber, ANY_VALUE(description) as description, SUM(quantity) as total_quantity
      FROM order_items
      GROUP BY partnumber
      ORDER BY total_quantity DESC
      LIMIT 10;
    `);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching most ordered products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/settings", (req, res) => {
  res.json(userSettings);
});
app.post("/settings", (req, res) => {
  const { theme, language, notifications } = req.body;
  // In a real app, save to the database
  userSettings.theme = theme;
  userSettings.language = language;
  userSettings.notifications = notifications;
  res.status(200).send("Settings updated");
});
// Assuming you are using Express and a database like PostgreSQL or MySQL

app.get("/api/salesdata/:productId", async (req, res) => {
  const { productId } = req.params;

  try {
    const salesData = await pool.query(
      `SELECT DATE(created_at) AS date, SUM(quantity) AS sales 
       FROM order_items 
       WHERE partnumber = $1
       GROUP BY DATE(created_at) 
       ORDER BY DATE(created_at)`,
      [productId]
    );

    res.json(salesData.rows);
  } catch (error) {
    console.error("Error fetching sales data:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: Token missing" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, secretKey);

    req.user = decoded; // Attach user info to req
    console.log("Authenticated user:", req.user); // Debug log

    next();
  } catch (err) {
    console.error("Authentication error:", err); // Log error details
    res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
};

app.post("/api/admin/create-admin", async (req, res) => {
  const { email, password, country, role } = req.body;

  // Ensure the role is provided
  if (!role) {
    return res.status(400).json({ error: "Role is required" });
  }

  // Retrieve the email of the admin who is creating the new admin
  const createdBy = req.user?.email || "system"; // Fallback to 'system' if `req.user.email` is not available

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new admin user into the database with the hashed password
    await pool.query(
      "INSERT INTO registration (email, password, country, role) VALUES (?, ?, ?, ?)",
      [email, hashedPassword, country, role]
    );

    // Log the creation action
    await pool.query(
      "INSERT INTO admin_audit_log (email, action, created_by, details) VALUES (?, ?, ?, ?)",
      [
        email,
        "create",
        createdBy,
        `Created admin with email=${email}, country=${country}, role=${role}`,
      ]
    );

    res.status(201).json({ message: "Admin created successfully" });
  } catch (error) {
    console.error("Error creating admin:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/admin/compare-countries", async (req, res) => {
  const { countries } = req.query;

  if (!countries || !Array.isArray(countries) || countries.length < 2) {
    return res
      .status(400)
      .json({ error: "Invalid or insufficient countries provided" });
  }

  const connection = await pool.getConnection();
  try {
    const countryPlaceholders = countries.map(() => "?").join(",");

    // Query to get the number of orders per country
    const ordersQuery = `
      SELECT country, COUNT(*) AS order_count
      FROM placing_orders
      WHERE country IN (${countryPlaceholders})
      GROUP BY country
    `;

    // Query to get the number of users per country
    const usersQuery = `
      SELECT country, COUNT(*) AS user_count
      FROM registration
      WHERE country IN (${countryPlaceholders})
      GROUP BY country
    `;

    // Execute both queries in parallel
    const [ordersResult] = await connection.query(ordersQuery, countries);
    const [usersResult] = await connection.query(usersQuery, countries);

    // Prepare the comparison data
    const comparisonData = countries.reduce((acc, country) => {
      acc[country] = {
        order_count: 0,
        user_count: 0,
      };
      return acc;
    }, {});

    ordersResult.forEach((row) => {
      comparisonData[row.country].order_count = row.order_count;
    });

    usersResult.forEach((row) => {
      comparisonData[row.country].user_count = row.user_count;
    });

    res.json(comparisonData);
  } catch (error) {
    console.error("Error comparing countries:", error);
    res.status(500).json({ error: "Error comparing countries" });
  } finally {
    connection.release();
  }
});

// Add this to your Express app

// Update your Express app with this endpoint
app.get("/api/admin/country-logins", async (req, res) => {
  try {
    // Fetch country logins excluding superadmin
    const query = `
      SELECT r.country AS country,
             COUNT(*) AS login_count
      FROM audit_logs al
      JOIN registration r ON al.email = r.email
      WHERE r.role != 'superadmin'
        AND al.action = 'login'
        AND al.timestamp >= DATE_SUB(CURDATE(), INTERVAL 4 MONTH)
      GROUP BY r.country
      ORDER BY login_count DESC;
    `;

    const [rows] = await pool.query(query);

    if (rows.length === 0) {
      return res.status(404).json({ message: "No login data found" });
    }

    res.status(200).json(rows);
  } catch (error) {
    console.error("Error fetching country logins:", error);
    res.status(500).json({ error: "Error fetching country logins" });
  }
});
app.post("/api/logout", async (req, res) => {
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




// API to fetch all logged-in users
app.get("/api/logged-in-users", async (req, res) => {
  const recentHours = 24; // Adjust this as needed

  // Calculate the cutoff time for recent logins
  const cutoffTime = new Date();
  cutoffTime.setHours(cutoffTime.getHours() - recentHours);

  const sql = `
    SELECT r.email, l.login_time
    FROM logins l
    JOIN registration r ON l.user_id = r.id
    WHERE l.login_time >= ?
    ORDER BY l.login_time DESC
  `;

  try {
    const [rows] = await pool.query(sql, [cutoffTime]);

    return res.json({
      message: "Fetched logged-in users successfully",
      data: rows
    });
  } catch (error) {
    console.error("Error fetching logged-in users:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});
app.get('/api/logins/hourly', async (req, res) => {
  const { date } = req.query;

  try {
    const query = `
      SELECT HOUR(login_time) AS hour, COUNT(*) AS count
      FROM logins
      WHERE DATE(login_time) = ?
      GROUP BY HOUR(login_time)
      ORDER BY hour;
    `;

    const [rows] = await pool.query(query, [date]);

    res.json(rows);
  } catch (error) {
    console.error('Error fetching logins count by hour:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/logins/count', async (req, res) => {
  try {
    const sql = "SELECT COUNT(*) AS count FROM logins"; // Adjust the query based on your schema
    const [results] = await pool.query(sql);
    res.json({ count: results[0].count });
  } catch (error) {
    console.error('Error fetching logged-in users count:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.get("/api/admins", async (req, res) => {
  try {
    const [admins] = await pool.query(
      `SELECT id, firstName AS name, email, role
       FROM registration
       WHERE role IN ('admin', 'superadmin','finance', 'warehouse')`
    );

    if (admins.length === 0) {
      console.log("No admins found");
      res.json([]);
    } else {
      res.json(admins);
    }
  } catch (error) {
    console.error("Error fetching admins:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/admins/:id/permissions", async (req, res) => {
  const { id } = req.params;

  try {
    const [permissions] = await pool.query(
      `SELECT create_permission, read_permission, update_permission, delete_permission
       FROM admin_rights
       WHERE user_id = ?`,
      [id]
    );

    if (permissions.length === 0) {
      console.log("No permissions found for admin:", id);
      res.status(404).json({ error: "No permissions found for admin" });
    } else {
      res.json(permissions[0]);
    }
  } catch (error) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/admin/update", async (req, res) => {
  const {
    user_id,
    role,
    create_permission,
    read_permission,
    update_permission,
    delete_permission,
  } = req.body;

  try {
    const [result] = await pool.query(
      `UPDATE admin_rights 
       SET role = ?, create_permission = ?, read_permission = ?, update_permission = ?, delete_permission = ? 
       WHERE user_id = ?`,
      [
        role,
        create_permission,
        read_permission,
        update_permission,
        delete_permission,
        user_id,
      ]
    );

    if (result.affectedRows === 0) {
      console.log("No rows updated");
      res.status(404).json({ error: "Admin not found" });
    } else {
      console.log("Admin rights updated successfully");
      res.json({ message: "Admin rights updated successfully" });
    }
  } catch (error) {
    console.error("Error updating admin rights:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Fetch permissions for a specific admin
app.get("/api/admins/:id/permissions", async (req, res) => {
  const { id } = req.params;
  try {
    const [permissions] = await pool.query(
      `SELECT create_permission, read_permission, update_permission, delete_permission
       FROM admin_rights
       WHERE user_id = ?`,
      [id]
    );
    if (permissions.length === 0) {
      res.status(404).json({ error: "No permissions found" });
    } else {
      res.json(permissions[0]);
    }
  } catch (error) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Create or update permissions for an admin
app.post("/api/admin/permissions", async (req, res) => {
  const {
    user_id,
    role,
    create_permission,
    read_permission,
    update_permission,
    delete_permission,
    manage_users_permission,
    manage_products_permission,
    manage_orders_permission,
    manage_clearorder_permission,
    approve_permission,
    pending_permission,
    cancel_permission,
    clear_permission,
  } = req.body;

  try {
    // Check if permissions already exist for the user
    const [existingPermissions] = await pool.query(
      `SELECT * FROM admin_rights WHERE user_id = ?`,
      [user_id]
    );

    if (existingPermissions.length === 0) {
      // Insert new permissions if they don't exist
      const [result] = await pool.query(
        `INSERT INTO admin_rights (
          user_id, role, create_permission, read_permission, update_permission, delete_permission,
          manage_users_permission, manage_products_permission, manage_orders_permission, manage_clearorder_permission,
          approve_permission, pending_permission, cancel_permission, clear_permission
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          user_id,
          role,
          create_permission,
          read_permission,
          update_permission,
          delete_permission,
          manage_users_permission,
          manage_products_permission,
          manage_orders_permission,
          manage_clearorder_permission,
          approve_permission,
          pending_permission,
          cancel_permission,
          clear_permission,
        ]
      );
      console.log("Permissions created successfully");
      res.json({ message: "Permissions created successfully" });
    } else {
      // Update existing permissions
      const [result] = await pool.query(
        `UPDATE admin_rights
         SET role = ?, create_permission = ?, read_permission = ?, update_permission = ?, delete_permission = ?,
             manage_users_permission = ?, manage_products_permission = ?, manage_orders_permission = ?, manage_clearorder_permission = ?,
             approve_permission = ?, pending_permission = ?, cancel_permission = ?, clear_permission = ?
         WHERE user_id = ?`,
        [
          role,
          create_permission,
          read_permission,
          update_permission,
          delete_permission,
          manage_users_permission,
          manage_products_permission,
          manage_orders_permission,
          manage_clearorder_permission,
          approve_permission,
          pending_permission,
          cancel_permission,
          clear_permission,
          user_id,
        ]
      );
      console.log("Permissions updated successfully");
      res.json({ message: "Permissions updated successfully" });
    }
  } catch (error) {
    console.error("Error creating/updating permissions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get("/api/admin/permissions/:adminId", async (req, res) => {
  const { adminId } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT create_permission, read_permission, update_permission, delete_permission, role,
              manage_users_permission, manage_products_permission, manage_orders_permission, manage_clearorder_permission,
              approve_permission, pending_permission, cancel_permission, clear_permission
       FROM admin_rights
       WHERE user_id = ?`,
      [adminId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Admin permissions not found" });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error("Error fetching admin permissions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Fetch audit logs
app.get("/api/audit-logs", async (req, res) => {
  try {
    const { date, time, changed_by } = req.query;
    let query = "SELECT * FROM audit_logs WHERE 1=1";

    if (date) {
      query += ` AND DATE(timestamp) = '${date}'`;
    }

    if (time) {
      // Construct datetime range
      const startTime = `${date} ${time}`;
      const endTime = `${date} ${time}:59`; // Ensure to include seconds in the end time for better accuracy
      query += ` AND timestamp BETWEEN '${startTime}' AND '${endTime}'`;
    }

    if (changed_by) {
      query += ` AND email LIKE '%${changed_by}%'`;
    }

    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching audit logs:", error);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

app.get("/api/all-audit-logs", async (req, res) => {
  try {
    const { date, time, changed_by } = req.query;
    let query = "SELECT * FROM audit_logs WHERE 1=1";
    let productQuery = "SELECT * FROM product_audit_log WHERE 1=1";

    if (date) {
      query += ` AND DATE(timestamp) = '${date}'`;
      productQuery += ` AND DATE(timestamp) = '${date}'`;
    }

    if (time) {
      const startTime = `${date} ${time}`;
      const endTime = `${date} ${time}:59`;
      query += ` AND timestamp BETWEEN '${startTime}' AND '${endTime}'`;
      productQuery += ` AND timestamp BETWEEN '${startTime}' AND '${endTime}'`;
    }

    if (changed_by) {
      query += ` AND email LIKE '%${changed_by}%'`;
      productQuery += ` AND changed_by LIKE '%${changed_by}%'`; // Adjust if different column
    }

    const [auditLogs] = await pool.query(query);
    const [productAuditLogs] = await pool.query(productQuery);

    const combinedLogs = [...auditLogs, ...productAuditLogs];
    combinedLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json(combinedLogs);
  } catch (error) {
    console.error("Error fetching audit logs:", error);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

app.get("/api/product-audit-logs", async (req, res) => {
  try {
    const { date, time, changed_by } = req.query;
    let query = "SELECT * FROM product_audit_log WHERE 1=1";

    if (date) {
      query += ` AND DATE(timestamp) = '${date}'`;
    }

    if (time) {
      const startTime = `${date} ${time}`;
      const endTime = `${date} ${time}:59`;
      query += ` AND timestamp BETWEEN '${startTime}' AND '${endTime}'`;
    }

    if (changed_by) {
      query += ` AND changed_by LIKE '%${changed_by}%'`; // Adjust if different column
    }

    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching product audit logs:", error);
    res.status(500).json({ error: "Failed to fetch product audit logs" });
  }
});

app.get("/api/admin/productOrderCount/:partnumber", async (req, res) => {
  const { partnumber } = req.params;

  if (!partnumber) {
    return res.status(400).json({ error: "Part number is required" });
  }

  try {
    // Query to get sales data grouped by month
    const [salesData] = await pool.query(
      `
      SELECT DATE_FORMAT(created_at, '%Y-%m') as month, SUM(quantity) as total_quantity
      FROM order_items
      WHERE partnumber = ?
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY DATE_FORMAT(created_at, '%Y-%m')
    `,
      [partnumber]
    );

    // If no data is found
    if (salesData.length === 0) {
      return res.status(404).json({ error: "Product not found or no sales data available" });
    }

    // Calculate total quantity
    const totalQuantity = salesData.reduce((sum, record) => sum + record.total_quantity, 0);

    // Return detailed response
    res.json({
      partnumber,
      totalQuantity,
      salesData,
      metadata: {
        recordCount: salesData.length,
        startMonth: salesData[0].month,
        endMonth: salesData[salesData.length - 1].month,
      }
    });
  } catch (error) {
    console.error("Error fetching order count for product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});



// In your Express app
app.post("/api/admin_rights/update", async (req, res) => {
  const {
    admin_id,
    create_permission,
    read_permission,
    update_permission,
    delete_permission,
  } = req.body;

  try {
    await pool.query(
      `INSERT INTO admin_rights (user_id, create_permission, read_permission, update_permission, delete_permission)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
       create_permission = VALUES(create_permission),
       read_permission = VALUES(read_permission),
       update_permission = VALUES(update_permission),
       delete_permission = VALUES(delete_permission)`,
      [
        admin_id,
        create_permission,
        read_permission,
        update_permission,
        delete_permission,
      ]
    );

    res.status(200).json({ message: "Admin rights updated successfully" });
  } catch (error) {
    console.error("Error updating admin rights:", error);
    res.status(500).json({ error: "Failed to update admin rights" });
  }
});

app.get("/api/admin/orders/status-counts", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching order counts by status
    let getCountsQuery = `
      SELECT 
        SUM(CASE WHEN placing_orders.status = 'Pending' THEN 1 ELSE 0 END) AS pending_count,
        SUM(CASE WHEN placing_orders.status = 'Approved' THEN 1 ELSE 0 END) AS approved_count,
        SUM(CASE WHEN placing_orders.status = 'Completed' THEN 1 ELSE 0 END) AS completed_count
      FROM placing_orders
    `;

    let queryParams = [];

    // If the user is not a superadmin, filter by country
    if (adminRole !== "superadmin" && adminCountryCode !== "SUPERADMIN") {
      getCountsQuery += " WHERE placing_orders.country = ?";
      queryParams.push(adminCountryCode);
    }

    // Execute the query to get counts
    const [counts] = await pool.query(getCountsQuery, queryParams);

    res.status(200).json(counts[0]);
  } catch (error) {
    console.error("Error fetching order status counts:", error);
    res.status(500).json({ error: "Error fetching order status counts" });
  }
});

// Assuming you're using Express.js and a MySQL database

app.get("/api/admin-email", async (req, res) => {
  const { userEmail } = req.query;

  if (!userEmail) {
    return res.status(400).json({ message: "User email is required" });
  }

  try {
    // Step 1: Fetch the current user's country
    const [userRows] = await pool.query(
      "SELECT country FROM registration WHERE email = ? LIMIT 1",
      [userEmail]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const countryCode = userRows[0].country;

    // Step 2: Fetch the admin email for the user's country
    const [adminRows] = await pool.query(
      "SELECT email FROM registration WHERE role = ? AND country = ? LIMIT 1",
      ["admin", countryCode]
    );

    if (adminRows.length > 0) {
      return res.json({ email: adminRows[0].email });
    } else {
      return res.status(404).json({ message: "Admin not found" });
    }
  } catch (error) {
    console.error("Error fetching admin email:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Fetch orders by email
// Ensure your backend route is correctly defined as shown below
app.get('/api/order-history/:email', (req, res) => {
  const { email } = req.params;
  console.log(`Received request for order history: ${email}`); // Log to confirm request received

  const query = `SELECT * FROM placing_orders WHERE email = ?`;

  // Log before the query execution
  console.log(`Executing query: ${query} with email: ${email}`);

  pool.query(query, [email], (err, results) => {
    // Log immediately after the query is executed
    console.log('Query executed');

    if (err) {
      console.error('Error fetching orders:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    // Log the results fetched
    console.log('Fetched Results:', results);

    if (results.length === 0) {
      return res.status(404).json({ message: 'No orders found for this email.' });
    }

    // Log just before sending the response
    console.log('Sending response to client');
    res.json(results);
  });
});

// Assuming you are using Express.js and have set up your pool for database connection
app.get("/api/company-sales-comparison", async (req, res) => {
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

    // Define the query to fetch sales by company in the admin's country
    let getSalesQuery = `
      SELECT company_name, SUM(CAST(totalprice AS DECIMAL(10, 2))) AS total_sales
      FROM placing_orders
      WHERE country = ?
      GROUP BY company_name
      ORDER BY total_sales DESC
    `;

    // Superadmins can see data for all countries; others see only their country
    const queryParams = [adminRole === "superadmin" ? "%" : adminCountryCode];

    const [sales] = await pool.query(getSalesQuery, queryParams);

    if (sales.length === 0) {
      return res.status(404).json({ message: "No sales data found for the specified country" });
    }

    res.status(200).json(sales);
  } catch (error) {
    console.error("Error fetching company sales comparison:", error);
    res.status(500).json({ error: "Error fetching sales data" });
  }
});






//////////////////////////////Admin/////////////////////////////////////////


/////////////////////////////Finance///////////////////////////////////////

app.get('/api/exchange-rates', async (req, res) => {
  try {
    const apiKey = '734e134b1dcdfe32c5e1d132'; // Use your actual API key
    const apiUrl = `https://v6.exchangerate-api.com/v6/${apiKey}/latest/USD`;

    // Fetch the exchange rates from the API
    const response = await axios.get(apiUrl);

    // Check if the response contains the rates
    if (response.data && response.data.conversion_rates) {
      const { TZS, UGX, KES } = response.data.conversion_rates;
      res.json({
        TZS_USD: TZS,
        UGX_USD: UGX,
        KES_USD: KES,
      });
    } else {
      console.error('Response data is missing conversion_rates:', response.data);
      res.status(500).json({ error: 'Failed to fetch exchange rates' });
    }
  } catch (error) {
    console.error('Error fetching exchange rates:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Error fetching exchange rates' });
  }
});
app.get("/api/finance-sales-by-month", async (req, res) => {
  const adminEmail = req.query.email;
  const startMonth = req.query.startMonth; // Format: YYYY-MM (start of the range)
  const endMonth = req.query.endMonth; // Format: YYYY-MM (end of the range)

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [adminEmail]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    // Define the base query for fetching monthly sales
    let getSalesQuery = `
      SELECT DATE_FORMAT(created_at, '%Y-%m') as month, SUM(totalprice) as total_sales
      FROM placing_orders
    `;

    let queryParams = [];

    // Filter by the specified date range, or default to the current year
    if (startMonth && endMonth) {
      getSalesQuery += " WHERE DATE_FORMAT(created_at, '%Y-%m') BETWEEN ? AND ?";
      queryParams.push(startMonth, endMonth);
    } else {
      // Default to the current year if no range is provided
      const currentYear = new Date().getFullYear();
      getSalesQuery += " WHERE YEAR(created_at) = ?";
      queryParams.push(currentYear);
    }

    // Filter by country based on the admin's role
    if (adminRole !== "superadmin") {
      getSalesQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    // Group the results by month and sum total sales
    getSalesQuery += " GROUP BY month ORDER BY month DESC";

    const [sales] = await pool.query(getSalesQuery, queryParams);

    if (sales.length === 0) {
      return res
        .status(404)
        .json({ message: "No sales found for the specified period" });
    }

    res.status(200).json(sales);
  } catch (error) {
    console.error("Error fetching sales by month:", error);
    res.status(500).json({ error: "Error fetching sales data" });
  }
});

app.get('/api/weekly-sales', async (req, res) => {
  const { start_date, end_date } = req.query;

  if (!start_date || !end_date) {
      return res.status(400).json({ error: "Please provide start_date and end_date query parameters." });
  }

  try {
      const query = `
          SELECT 
              DATE_FORMAT(created_at, '%Y-%u') AS year_week,
              SUM(totalprice) AS weekly_sales
          FROM 
              placing_orders
          WHERE
              created_at BETWEEN ? AND ?
          GROUP BY 
              year_week
          ORDER BY 
              year_week;
      `;

      const [results] = await pool.query(query, [start_date, end_date]);

      if (results.length === 0) {
          return res.status(404).json({ error: 'No sales data found for the given period.' });
      }

      return res.status(200).json(results);
  } catch (error) {
      console.error('Error fetching weekly sales:', error);
      return res.status(500).json({ error: 'An error occurred while fetching the data.' });
  }
});
app.get('/api/monthly-sales', async (req, res) => {
  const endDate = moment().format('YYYY-MM-DD');
  const startDate = moment().subtract(5, 'months').startOf('month').format('YYYY-MM-DD');

  try {
    const query = `
      SELECT 
    YEAR(created_at) AS year, 
    MONTH(created_at) AS month, 
    SUM(CAST(totalprice AS DECIMAL(10, 2))) AS monthly_sales
FROM placing_orders
GROUP BY YEAR(created_at), MONTH(created_at)
ORDER BY YEAR(created_at), MONTH(created_at);
    `;

    const [results] = await pool.query(query, [startDate, endDate]);


    return res.status(200).json(results);
  } catch (error) {
    console.error('Error fetching monthly sales:', error);
    return res.status(500).json({ error: 'An error occurred while fetching the data.' });
  }
});

app.get('/api/daily-sales', async (req, res) => {
  // Set the date range for this month and last month
  const today = moment().format('YYYY-MM-DD');
  const startOfThisMonth = moment().startOf('month').format('YYYY-MM-DD');
  const startOfLastMonth = moment().subtract(1, 'month').startOf('month').format('YYYY-MM-DD');
  const endOfLastMonth = moment().subtract(1, 'month').endOf('month').format('YYYY-MM-DD');

  try {
    // Query to get daily sales for this month
    const queryThisMonth = `
      SELECT 
        DATE(created_at) AS date, 
        SUM(CAST(totalprice AS DECIMAL(10, 2))) AS daily_sales
      FROM placing_orders
      WHERE created_at BETWEEN ? AND ?
      GROUP BY DATE(created_at)
      ORDER BY DATE(created_at);
    `;

    // Query to get daily sales for last month
    const queryLastMonth = `
      SELECT 
        DATE(created_at) AS date, 
        SUM(CAST(totalprice AS DECIMAL(10, 2))) AS daily_sales
      FROM placing_orders
      WHERE created_at BETWEEN ? AND ?
      GROUP BY DATE(created_at)
      ORDER BY DATE(created_at);
    `;

    // Execute the queries
    const [resultsThisMonth] = await pool.query(queryThisMonth, [startOfThisMonth, today]);
    const [resultsLastMonth] = await pool.query(queryLastMonth, [startOfLastMonth, endOfLastMonth]);

    // Combine the results
    return res.status(200).json({
      thisMonth: resultsThisMonth,
      lastMonth: resultsLastMonth,
    });
  } catch (error) {
    console.error('Error fetching daily sales:', error);
    return res.status(500).json({ error: 'An error occurred while fetching the data.' });
  }
});




app.get("/api/finance-sales-current-previous-month", async (req, res) => {
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    // Fetch the admin's country and role from the registration table
    const countryCodeQuery =
      "SELECT country, role FROM registration WHERE email = ?";
    const [countryCodeResult] = await pool.query(countryCodeQuery, [
      adminEmail,
    ]);

    if (countryCodeResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryCodeResult[0];

    const currentMonth = new Date();
    const currentMonthStr = currentMonth.toISOString().slice(0, 7); // YYYY-MM
    const previousMonth = new Date(currentMonth.setMonth(currentMonth.getMonth() - 1));
    const previousMonthStr = previousMonth.toISOString().slice(0, 7); // YYYY-MM

    // Define the query to fetch sales for the current and previous month
    let getSalesQuery = `
      SELECT DATE_FORMAT(created_at, '%Y-%m') as month, SUM(totalprice) as total_sales
      FROM placing_orders
      WHERE DATE_FORMAT(created_at, '%Y-%m') IN (?, ?)
    `;

    let queryParams = [currentMonthStr, previousMonthStr];

    // Filter by country based on the admin's role
    if (adminRole !== "superadmin") {
      getSalesQuery += " AND country = ?";
      queryParams.push(adminCountryCode);
    }

    getSalesQuery += " GROUP BY month ORDER BY month DESC";

    const [sales] = await pool.query(getSalesQuery, queryParams);

    if (sales.length === 0) {
      return res.status(404).json({ message: "No sales data found for the specified period" });
    }

    res.status(200).json(sales);
  } catch (error) {
    console.error("Error fetching sales for current and previous months:", error);
    res.status(500).json({ error: "Error fetching sales data" });
  }
});

app.get('/api/order-stats', async (req, res) => {
  try {
      const [results] = await pool.query(`
          SELECT 
              COUNT(*) AS total_orders,
              SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_orders
          FROM placing_orders
      `);

      res.json(results);
  } catch (error) {
      console.error('Error fetching order stats:', error);
      res.status(500).json({ message: 'Failed to fetch order stats' });
  }
});
app.get('/api/order-transit-count', async (req, res) => {
  try {
      const [rows] = await pool.query(
          'SELECT COUNT(*) AS total_orders_transit FROM placing_orders WHERE status = ?',
          ['On Transit']
      );

      res.json({ total_orders_transit: rows[0].total_orders_transit });
  } catch (error) {
      console.error('Error fetching order transit count:', error);
      res.status(500).json({ error: 'Could not fetch order transit count. Please try again later.' });
  }
});

app.get("/api/finance/orders/history", async (req, res) => {
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

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found for this email" });
    }

    const formattedOrders = orders.map((order) => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
    }));

    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders" });
  }
});





////////////////////////////Finance/////////////////////////////////////////



///////////////////////////settings//////////////////////////////////////////

app.get('/api/settings/countries', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM countries');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching countries:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add a new country
app.post('/api/add/countries', async (req, res) => {
  const { code, name } = req.body;
  try {
    const [result] = await pool.query(
      'INSERT INTO countries (code, name) VALUES (?, ?)',
      [code, name]
    );
    const [rows] = await pool.query('SELECT * FROM countries WHERE code = ?', [code]);
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Error adding country:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Delete a country
app.delete('/api/remove/countries/:code', async (req, res) => {
  const { code } = req.params;
  try {
    await pool.query('DELETE FROM countries WHERE code = ?', [code]);
    res.status(204).end();
  } catch (error) {
    console.error('Error deleting country:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/api/send-invoice', async (req, res) => {
  const { client, items, orderNumber, total } = req.body;

  const INVOICE_NINJA_URL = 'http://localhost:8000/api/v1';
  const API_TOKEN = 'lplYeuCJfmmcWfhPdJ9BHA1GcBuU7aBQHmY4K1xBpxU2RhB3Tr8y0VcZL3QHNDFB';

  try {
    // 1. Create or get client
    let clientId;
    let contact = null;
    // Try to find client by email
    const searchResponse = await fetch(`${INVOICE_NINJA_URL}/clients?email=${client.email}`, {
      headers: {
        'X-API-Token': API_TOKEN,
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    const searchData = await searchResponse.json();
    console.log('Client search response:', searchData);
    if (searchData.data && Array.isArray(searchData.data) && searchData.data.length > 0) {
      clientId = searchData.data[0].id;
      const clientObj = searchData.data[0];
      contact = clientObj.contacts && clientObj.contacts.length > 0 ? clientObj.contacts[0] : null;
    } else {
      // Create client
      const createClientResponse = await fetch(`${INVOICE_NINJA_URL}/clients`, {
        method: 'POST',
        headers: {
          'X-API-Token': API_TOKEN,
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({
          name: client.name,
          email: client.email,
          phone: client.phone || '',
          address1: client.address1 || '',
          address2: client.address2 || '',
          city: client.city || '',
          state: client.state || '',
          postal_code: client.zip || '',
          country_id: client.country || 1,
          contacts: [{
            email: client.email,
            first_name: client.name.split(' ')[0],
            last_name: client.name.split(' ')[1] || ''
          }]
        })
      });
      const createClientData = await createClientResponse.json();
      console.log('Client create response:', createClientData);
      if (!createClientData.data || !createClientData.data.id) {
        return res.status(500).json({ error: 'Failed to create client', details: createClientData });
      }
      clientId = createClientData.data.id;
      contact = createClientData.data.contacts && createClientData.data.contacts.length > 0 ? createClientData.data.contacts[0] : null;
    }

    if (!contact || !contact.email) {
      return res.status(500).json({ error: 'Client does not have a valid contact with email.' });
    }

    const lineItems = items.map(item => ({
      product_key: item.product_key || item.name,
      notes: item.notes || item.description || '',
      cost: parseFloat(item.cost || item.price),
      qty: parseInt(item.quantity),
      tax_name1: 'VAT',
      tax_rate1: 10
    }));

    const invoiceData = {
      client_id: clientId,
      line_items: lineItems,
      invoice_number: orderNumber,
      po_number: orderNumber,
      terms: 'Net 30',
      footer: 'Thank you for your business!',
      public_notes: `Order Number: ${orderNumber}`,
      private_notes: `Order placed on ${new Date().toISOString()}`,
      contacts: [{ id: contact.id, email: contact.email }]
    };

    const createInvoiceResponse = await fetch(`${INVOICE_NINJA_URL}/invoices`, {
      method: 'POST',
      headers: {
        'X-API-Token': API_TOKEN,
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(invoiceData)
    });

    const createInvoiceData = await createInvoiceResponse.json();
    console.log('Invoice creation response:', createInvoiceData);

    if (!createInvoiceResponse.ok) {
      return res.status(500).json({ error: 'Failed to create invoice', details: createInvoiceData });
    }

    const invoiceId = createInvoiceData.data.id;

    // 3. Send invoice email
    const sendEmailResponse = await fetch(`${INVOICE_NINJA_URL}/email_invoice`, {
      method: 'POST',
      headers: {
        'X-API-Token': API_TOKEN,
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({
        invoices: [{ id: invoiceId }]
      })
    });

    if (!sendEmailResponse.ok) {
      return res.status(500).json({ error: 'Invoice created but failed to send email' });
    }

    res.json({
      success: true,
      message: 'Invoice created and sent successfully',
      invoiceId: invoiceId
    });

  } catch (error) {
    console.error('Invoice Ninja integration error:', error);
    res.status(500).json({ error: 'Failed to process invoice' });
  }
});


///////////////////////////settings/////////////////////////////////////////

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