const express = require('express');
const mysql = require('mysql2/promise');
const app = express();
const cors = require('cors');
const fs = require('fs');
const path = require('path')
const https = require('https');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const session = require('express-session');

require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.json());
app.use(cors());
app.use(cors({
  origin: 'https://localhost:3000', // Allow requests from this origin
  credentials: true, // Allow credentials (e.g., cookies) to be sent in requests
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow these HTTP methods
  headers: ['Content-Type', 'Authorization'] 
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true } // Set to true if using HTTPS
}));

// Try to read SSL certificates with error handling
let ssl;
try {   
  ssl = {
    ca: fs.readFileSync(path.join(__dirname,'cert','server-ca.pem' )),
    key: fs.readFileSync(path.join(__dirname,'cert','client-key.pem' )),
    cert: fs.readFileSync(path.join(__dirname,'cert','client-cert.pem' ))
  };
  
} catch (error) {
  console.error('Error loading SSL certificates:', error);
}
salt=10;

let pool;
try {
  pool = mysql.createPool({
    host: process.env.INSTANCE_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DATABASE,
    port: process.env.DB_PORT,
    ssl: ssl,
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 20000,
    queueLimit: 0,
  });
 
} catch (error) {
  console.error('Error creating database connection pool:', error);
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
const httpsServer = https.createServer(ssl, app);

if (process.env.NODE_ENV === 'production') {
  pool.socketPath = process.env.DB_SOCKET_PATH;
} else {
  pool.host = process.env.INSTANCE_HOST;
 
}





  app.post('/api/register', (req, res) => {
    const query = `
      INSERT INTO registration (
        companyName, title, firstName, secondName, address1, address2, city, zip, phone, email, password, country
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
  
    // Extract saltRounds from your environment variables or set it to a default value
    const saltRounds = parseInt(process.env.SALT_ROUNDS) || 10;
  
    bcrypt.hash(req.body.password.toString(), saltRounds, (err, hash) => {
      if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).json({ error: 'Error hashing password' });
      }
  
      // Destructure the request body to get the registration details
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
        country
      } = req.body;
  
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
        email,
        hash, // Use the hashed password
        country
      ];
  
      pool.query(query, values, (err, results) => {
        if (err) {
          console.error('Error inserting data into MySQL:', err);
          return res.status(500).send('Server error');
        }
        res.status(200).send('User registered successfully');
      });
    });
  });
  
  app.post('/login', (req, res) => {
    const sql = "SELECT * FROM registration WHERE email = ? AND password = ?";
    pool.query(sql, [req.body.email, req.body.password])
      .then(([rows, fields]) => {
        if (rows.length > 0) {
          return res.json("Login Successfull");
          
        }
        return res.json(rows);
      })
      .catch(err => {
        console.error(err);
        return res.json("Login Failed");
      });
  });
  

app.get('/myproducts/:companyId', async (req, res) => {
  const { companyId } = req.params;

  try {
      const [company] = await pool.query('SELECT country FROM Registration WHERE id = ?', [companyId]);

      if (company.length === 0) {
          return res.status(404).json({ error: 'Company not found' });
      }

      const countryCode = company[0].country;

      const [products] = await pool.query(
          `SELECT p.partnumber,p.Description, pr.price
          FROM fulldata p
          JOIN atlascopcoproduct_prices pr ON p.id = pr.productId
          WHERE pr.countryCode = ?`,
          [countryCode]
      );

      res.json(products);
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

app.get('/myproducts/kenya', async (req, res) => {
  try {
      const [products] = await pool.query(
          `SELECT p.Description, pr.price
          FROM fulldata p
          JOIN atlascopcoproduct_prices pr ON p.id = pr.productId
          WHERE pr.countryCode = 'KE'`
      );

      res.json(products);
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});
  

app.get('/api/products/:category?', async (req, res) => {
  const category = req.params.category;

 

  let query;
  let queryParams = [];

  if (category) {
    query = `
      SELECT p.id, p.partnumber, p.Description, p.Price, s.quantity
      FROM fulldata p
      JOIN stock s ON p.id = s.product_id
      WHERE p.mainCategory = ? OR p.subCategory = ?
    `;
    queryParams = [category, category];
  } else {
    query = `
      SELECT p.id, p.partnumber, p.Description, p.Price, s.quantity
      FROM fulldata p
      JOIN stock s ON p.id = s.product_id
    `;
  }

  try {
   
    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error('Error executing query:', err);
    res.status(500).send('Internal Server Error');
  }
});

 

 
app.get('/api/Countryproducts/:country?', async (req, res) => {
  const { country } = req.params;

  let query;
  let queryParams;

  if (country) {
    query = `
      SELECT p.id, p.partnumber, p.Description, 
             IFNULL(cp.price, p.Price) AS Price, SUM(s.quantity) AS quantity
      FROM fulldata p
      LEFT JOIN atlascopcoproduct_prices cp ON p.id = cp.product_id AND cp.country_code = ?
      JOIN stock s ON p.id = s.product_id
      GROUP BY p.id, p.partnumber, p.Description, IFNULL(cp.price, p.Price)
    `;
    queryParams = [country];
  } else {
    query = `
      SELECT p.id, p.partnumber, p.Description, 
             p.Price, SUM(s.quantity) AS quantity
      FROM fulldata p
      JOIN stock s ON p.id = s.product_id
      GROUP BY p.id, p.partnumber, p.Description, p.Price
    `;
    queryParams = [];
  }

  try {
    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error('Error executing query:', err);
    res.status(500).send('Internal Server Error');
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

app.get('/api/search', async (req, res) => {
  const searchTerm = req.query.term || '';
  const category = req.query.category || '';

  let query = `
    SELECT p.id, p.partnumber, p.Description, p.Price, s.quantity, p.subCategory AS category
    FROM fulldata p
    JOIN stock s ON p.id = s.product_id
    WHERE (p.partnumber LIKE ? OR p.Description LIKE ? OR p.mainCategory LIKE ?)
  `;

  const searchValue = `%${searchTerm}%`;
  const queryParams = [searchValue, searchValue, searchValue];

  if (category) {
    query += ' AND (p.mainCategory = ? OR p.subCategory = ?)';
    queryParams.push(category, category);
  }

  try {
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

  try {
    const query = `
      SELECT p.partnumber, p.Description, p.Price
      FROM fulldata p
      WHERE p.partnumber = ?
    `;
    const [results] = await pool.query(query, [partnumber]);

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