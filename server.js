const express = require('express');
const mysql = require('mysql2');
const app = express();
const cors = require('cors');
require('dotenv').config(); 


app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3002', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '10028mike.',
  database: 'atlascopco'

});


module.exports = connection;
// MySQL connection

{/**
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '10028mike.',
  database: 'atlascopco'


  username: process.env.DB_USERNAME,
password: process.env.DB_PASSWORD,
database: process.env.DATABASE,
port: process.env.DB_PORT,
host:process.env.DB_HOST
});
 */}
connection.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
  } else {
    console.log('Connected to MySQL');
  }
});


app.get('/api/data', (req, res) => {
  connection.query('SELECT * FROM products', (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

app.get('api/products', (req, res) => {
  const { minPrice, maxPrice } = req.query;

  res.json({ minPrice, maxPrice });
});;

app.get('/api/servkit', (req, res) => {
  connection.query('SELECT * FROM servkit', (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});


app.get('/api/search', (req, res) => {
  const searchTerm = req.query.term;
  if (!searchTerm) {
      return res.status(400)
          .json(
              {
                  error: 'Search term is required'
              }
          );
  }

  const query = `
  SELECT * FROM products
  WHERE Description LIKE ? OR partnumber LIKE ?
`;

  const searchValue = `%${searchTerm}%`;

  connection.query(query, [searchValue, searchValue],
      (err, results) => {
          if (err) {
              console
                  .error('Error executing search query:', err);
              return res.status(500)
                  .json(
                      {
                          error: 'Internal server error'
                      });
          }

          res.json(results);
      });
});

app.post('/api/order', async (req, res) => {
  const { formData, cartItems, orderNumber } = req.body;

  if (!formData || !cartItems) {
    return res.status(400).json({ error: 'No form data or cart items provided' });
  }

  try {
 
    await connection.promise().query('START TRANSACTION');

   
    const [orderResult] = await connection.promise().query(
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
      await connection.promise().query(
        `INSERT INTO order_items (order_id, description, quantity, price) 
         VALUES (?, ?, ?, ?)`,
        [orderId, item.Description, item.quantity, item.Price]
      );
    }

    await connection.promise().query('COMMIT');
    res.status(201).json({ message: 'Order placed successfully', orderId });

  } catch (error) {

    await connection.promise().query('ROLLBACK');
    console.error('Error placing order:', error);
    res.status(500).send(error);
  }
});




const port = process.env.PORT || 3001;


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


app.get('/api/test-connection', (req, res) => {
  connection.query('SELECT 1 + 1 AS solution', (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.json({ message: 'Database connected', solution: results[0].solution });
  });
});
