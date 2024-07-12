const express = require('express');
const mysql = require('mysql2/promise');
const app = express();
const cors = require('cors');
const fs = require('fs');
const path = require('path')
const https = require('https');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const Joi = require('joi');
require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.use(cors)
app.use(express.json());
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', 'https://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'cert', 'client-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'cert', 'client-cert.pem')),
  ca: fs.readFileSync(path.join(__dirname, 'cert', 'server-ca.pem')),
};
salt=10;

let pool;

try {
  pool = mysql.createPool({
    host: process.env.INSTANCE_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DATABASE,
    port: process.env.DB_PORT,
    ssl: sslOptions,
    
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 20000,
    queueLimit: 0,
  });
  
 
} catch (error) {
  console.error('Error creating database connection pool:', error);
  process.exit(1); // Exit the process or handle the error as appropriate
}


{/** 
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'atlascorpobusiness/build')));
socketPath: process.env.DB_SOCKET_PATH,
*/}
app.get('/', (req, res) => {
  res.send('Hello World!');
});
const httpsServer = https.createServer({
  ...sslOptions,
  // Set the hostname to your domain name (e.g., example.com)
  servername: 'https://localhost:3001',
}, app);

if (process.env.NODE_ENV === 'production') {
  pool.socketPath = process.env.DB_SOCKET_PATH;
} else {
  pool.host = process.env.INSTANCE_HOST;
 
}

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
    confpassword: Joi.string().valid(Joi.ref('password')).required(), // Added for validation
    country: Joi.string().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    console.error('Validation error:', error.details);
    return res.status(400).json({ error: error.details });
  }
  next();
};

app.post('/api/register', validateInput, async (req, res) => {
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
    country
  } = req.body;

  const normalizedEmail = email.toLowerCase(); // Normalize the email address to lowercase

  try {
    const checkEmailQuery = 'SELECT email FROM registration WHERE LOWER(email) = LOWER(?)';
    const [result] = await pool.query(checkEmailQuery, [normalizedEmail]);

    if (result.length > 0) {
      console.error('Email already exists:', normalizedEmail);
      return res.status(400).json({ error: 'Email already exists' });
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
      country
    ];

    await pool.query(insertQuery, values);

   
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

//const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

//await sendVerificationEmail(email, firstName, verificationToken);

app.get('/verify-email', (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  const query = 'UPDATE registration SET is_verified = 1 WHERE email = ?';

  pool.query(query, [email], (err, result) => {
    if (err) {
      console.error('Error updating email verification:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Email not found' });
    }

    return res.status(200).json({ message: 'Email verified successfully' });
  });
});




const secretKey = 'waweru';

app.post('/login', (req, res) => {
    const sql = "SELECT * FROM registration WHERE email = ? AND password = ?";
    pool.query(sql, [req.body.email, req.body.password])
        .then(([users]) => {
            if (users.length > 0) {
                const user = users[0];
                const token = jwt.sign({ email: user.email }, secretKey, { expiresIn: '1h' });
                return res.json({ message: "Login Successful", token });
            } else {
                return res.status(401).json({ message: "Login Failed" });
            }
        })
        .catch(err => {
            console.error(err);
            return res.status(500).json({ message: "Internal Server Error" });
        });
});

app.post('/verifyToken', (req, res) => {
    const token = req.body.token;
    if (!token) {
        return res.status(401).json({ message: "Token required" });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        }
        res.json({ email: decoded.email });
    });
});
  

app.get('/api/myproducts', async (req, res) => {
    const userEmail = req.query.email;
  
    if (!userEmail) {
      console.error('No user email provided');
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    try {
     
      const countryCodeQuery = 'SELECT country FROM registration WHERE email =?';
      const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);
  
      if (countryCodeResult.length === 0) {
        console.error(`User not found with email: ${userEmail}`);
        return res.status(404).json({ error: 'User not found' });
      }
  
      const userCountryCode = countryCodeResult[0].country;
      console.log(`User country code: ${userCountryCode}`);
  
     
      const productsQuery = `
        SELECT p.id, p.partnumber, p.Description, p.image,p.thumb1,p.thumb2, pp.price AS Price, s.quantity
        FROM fulldata p
        JOIN stock s ON p.id = s.product_id
        JOIN atlascopcoproduct_prices pp ON p.id = pp.product_id
        WHERE pp.country_code =?
      `;
      const [products] = await pool.query(productsQuery, [userCountryCode]);
  
      console.log(`Fetched ${products.length} products`);
      res.json(products);
     
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

app.get('/api/user', async (req, res) => {
    const userEmail = req.query.email;
  
    if (!userEmail) {
      console.error('No user email provided');
      return res.status(401).json({ error: 'Unauthorized' });
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
        return res.status(404).json({ error: 'User not found' });
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
        country: userData.country
      });
    } catch (error) {
      console.error('Error fetching user data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.put('/api/user/update', async (req, res) => {
    const { email, companyName, title, firstName, secondName, address1, address2, city, zip, phone, country } = req.body;
  
   
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
  
    try {
      
      const query = `
        UPDATE registration
        SET companyName = ?, title = ?, firstName = ?, secondName = ?, address1 = ?,
            address2 = ?, city = ?, zip = ?, phone = ?, country = ?
        WHERE email = ?
      `;
      const values = [companyName, title, firstName, secondName, address1, address2, city, zip, phone, country, email];
  
      
      const [result] = await pool.query(query, values);
  
      
      if (result.affectedRows > 0) {
        res.json({ message: 'User details updated successfully' });
      } else {
        res.status(404).json({ error: 'User not found' });
      }
    } catch (error) {
      console.error('Error updating user data:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  
 
  app.get('/api/products/:category?', async (req, res) => {
    const category = req.params.category;
    const userEmail = req.query.email;
  
    if (!userEmail) {
      console.error('No user email provided');
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    try {
      
      const countryCodeQuery = 'SELECT country FROM registration WHERE email =?';
      const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);
  
      if (countryCodeResult.length === 0) {
        console.error(`User not found with email: ${userEmail}`);
        return res.status(404).json({ error: 'User not found' });
      }
  
      const userCountryCode = countryCodeResult[0].country;
      console.log(`User country code: ${userCountryCode}`);
  
      let query;
      let queryParams = [userCountryCode];
  
      if (category) {
        query = `
          SELECT p.id, p.partnumber, p.Description, p.image,p.thumb1,p.thumb2, pp.price AS Price, s.quantity
          FROM fulldata p
          JOIN stock s ON p.id = s.product_id
          JOIN atlascopcoproduct_prices pp ON p.id = pp.product_id
          WHERE (p.mainCategory = ? OR p.subCategory = ?) AND pp.country_code =?
        `;
        queryParams = [category, category, userCountryCode];
      } else {
        query = `
          SELECT p.id, p.partnumber, p.Description, p.image,p.thumb1,p.thumb2, pp.price AS Price, s.quantity
          FROM fulldata p
          JOIN stock s ON p.id = s.product_id
          JOIN atlascopcoproduct_prices pp ON p.id = pp.product_id
          WHERE pp.country_code =?
        `;
      }
  
      const [results] = await pool.query(query, queryParams);
      console.log(`Fetched ${results.length} products`);
      res.json(results);
    } catch (err) {
      console.error('Error fetching products:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  

 
app.post('/api/order', async (req, res) => {
  const { formData, cartItems, orderNumber } = req.body;
  if (!formData || !cartItems) {
    return res.status(400).json({ error: 'No form data or cart items provided' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [orderResult] = await connection.query(
      `INSERT INTO placing_orders (company_name, title, first_name, second_name, address1, address2, city, zip, phone, email, ordernumber) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        orderNumber
      ]
    );
    const orderId = orderResult.insertId;
    for (const item of cartItems) {
      await connection.query(
        `INSERT INTO order_items (order_id, description, quantity, price) 
         VALUES (?, ?, ?, ?)`,
        [orderId, item.Description, item.quantity, item.Price]
      );
    }
    await connection.commit();
    res.status(201).json({ message: 'Order placed successfully', orderId });
  } catch (error) {
    await connection.rollback();
    console.error('Error placing order:', error);
    res.status(500).send(error);
  } finally {
    connection.release();
  }
});

app.get('/api/orders', async (req, res) => {
  const userId = req.query.userId;
  const query = 'SELECT * FROM orders WHERE userId = ? ORDER BY orderDate DESC';

  try {
    const [results] = await pool.query(query, [userId]);
    res.json(results);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).send('Error fetching orders');
  }
});
app.get('/api/orders/history', async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: 'Email parameter is required' });
  }

  try {
    // Fetch orders and their items from database based on userEmail
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
      return res.status(404).json({ message: 'No orders found for this email' });
    }

    // Parse items JSON and format response
    const formattedOrders = orders.map(order => ({
      ...order,
      items: order.items ? JSON.parse(`[${order.items}]`) : []
    }));

    // Respond with the fetched orders
    res.status(200).json(formattedOrders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Error fetching orders' });
  }
});



app.get('/api/search', async (req, res) => {
  const searchTerm = req.query.term || '';
  const category = req.query.category || '';
  const userEmail = req.query.email;

  if (!userEmail) {
    console.error('No user email provided');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Fetch the country code based on user's email from the registration table
    const countryCodeQuery = 'SELECT country FROM registration WHERE email = ?';
    const [countryCodeResult] = await pool.query(countryCodeQuery, [userEmail]);

    if (countryCodeResult.length === 0) {
      console.error(`User not found with email: ${userEmail}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const userCountryCode = countryCodeResult[0].country;
    console.log(`User country code: ${userCountryCode}`);

    let query = `
      SELECT p.id, p.partnumber, p.Description, p.image,p.thumb1,p.thumb2, pp.price AS Price, s.quantity, p.subCategory AS category
      FROM fulldata p
      JOIN stock s ON p.id = s.product_id
      JOIN atlascopcoproduct_prices pp ON p.id = pp.product_id
      WHERE pp.country_code = ? AND (p.partnumber LIKE ? OR p.Description LIKE ? OR p.mainCategory LIKE ?)
    `;

    const searchValue = `%${searchTerm}%`;
    const queryParams = [userCountryCode, searchValue, searchValue, searchValue];

    if (category) {
      query += ' AND (p.mainCategory = ? OR p.subCategory = ?)';
      queryParams.push(category, category);
    }

    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error('Error executing search query:', err);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/api/products/range/:category/:min/:max', async (req, res) => {
  const category = req.params.category;
  const minPrice = parseFloat(req.params.min); // Parse min price as float
  const maxPrice = parseFloat(req.params.max); // Parse max price as float

  let query;
  let queryParams = [minPrice, maxPrice, category, category]; // Update queryParams order

  query = `
    SELECT p.id, p.partnumber, p.Description, p.Price, s.quantity
    FROM fulldata p
    JOIN stock s ON p.id = s.product_id
    WHERE (p.mainCategory = ? OR p.subCategory = ?) AND p.Price >= ? AND p.Price <= ?
  `;

  try {
    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error('Error fetching products by price range and category:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/api/products/partnumber/:partnumber', async (req, res) => {
  const { partnumber } = req.params;
  const userEmail = req.query.email; // Retrieve email from query parameters

  try {
    // Validate userEmail if required
    if (!userEmail) {
      return res.status(400).json({ message: 'Email is required' });
    }

    // Fetch product details along with price for the user's country
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
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




const port = process.env.PORT || 3001;
httpsServer.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

app.get('/api/test-connection', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT 1 + 1 AS solution');
    res.json({ message: 'Database connected', solution: results[0].solution });
  } catch (err) {
    console.error('Error executing query:', err);
    res.status(500).send(err);
  }
});