const express = require('express');
const mysql = require('mysql2');
const app = express();
const path = require('path');
const cors = require('cors');
require('dotenv').config(); 


// Serve the static files from the React app
app.use(express.static(path.join(__dirname, 'build')));

// Handles any requests that don't match the ones above
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});
{/**
async function fetchtext(){
  let url='https:/ipinfo.io/json?token=19349ef51244e4'
  let response = await fetch(url)
  let data = await response.json()
  
  console.log(data.country);
}
fetchtext();
 */}


app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const connection = mysql.createConnection({
  host:process.env.INSTANCE_HOST,
  user: process.env.DB_USERNAME,
password: process.env.DB_PASSWORD,
database: process.env.DATABASE,
port: process.env.DB_PORT,

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,



});

module.exports = connection;

// MySQL connection

{/**
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '10028mike.',
  database: 'atlascopco'

  
    host:'34.122.70.186',
  user:'atlascopco_admin',
  password:'10028mike.',
  database:'AtlasCopco',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  const dbConfig = {
  host: '34.122.70.186',
  user: 'atlascopco_admin',
  password: '10028mike.',
  database: 'AtlasCopco',
  ssl: {
    ca: fs.readFileSync('path/to/ssl/cert.pem'),
    key: fs.readFileSync('path/to/ssl/key.pem'),
    cert: fs.readFileSync('path/to/ssl/cert.pem')
  }
};

const connection = await mysql.createConnection(dbConfig);


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

app.get('/', (req, res) => {
  res.send('Hello World!');
});


app.get('/api/fulldata', (req, res) => {
  connection.query('SELECT * FROM fulldata', (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

app.get('/api/products/:category', (req, res) => {
  const category = req.params.category;


  const query = `
    SELECT * FROM fulldata WHERE subCategory LIKE ? OR mainCategory LIKE ?
  `;

  connection.query(query, [`%${category}%`, `%${category}%`], (err, results) => {
    if (err) {
     
      res.status(500).send(err);
    } else {
   
      res.json(results);
    }
  });

});


//////////////////////////API REQUESTS//////////////////////////////



app.get('/api/products', (req, res) => {
  const countryCode = req.query.country;

  const query = `
    SELECT name, description,pr.price
    FROM atlascopcoproducts p
    JOIN atlascopcoproduct_prices pr ON p.id = pr.product_id
    WHERE pr.country_code = ?
  `;

  connection.query(query, [countryCode], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      res.status(500).send('Internal Server Error');
    } else {
      res.json(results);
    }
  });
});
//getting filterelements category from db
app.get('/api/filterelement', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%filterelement%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting oilfilterelements category from db
app.get('/api/oilfilterelement', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%oilfilterelement%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting servkit category from db
app.get('/api/servkitfulldata', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%servkit%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting autodrainvalve category from db
app.get('/api/autodrainvalve', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%autodrainvalve%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting contractor category from db
app.get('/api/contractor', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%contractor%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting overhaulkit category from db
app.get('/api/overhaulkit', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%overhaulkit%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});
//getting silencerkit category from db
app.get('/api/silencerkit', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE mainCategory LIKE ?', ['%silencerkit%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});
//getting maintenancekit category from db
app.get('/api/maintenancekit', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE mainCategory LIKE ?', ['%maintenancekit%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting bearingkits category from db
app.get('/api/bearingkits', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%bearingkits%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting prevmain category from db
app.get('/api/prevmain', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%prevmain%'], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

//getting hrkit category from db
app.get('/api/hrkit', (req, res) => {
  connection.query('SELECT * FROM fulldata WHERE subCategory LIKE ?', ['%hrkit%'], (err, results) => {
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
  SELECT * FROM fulldata
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
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const userLocation = req.query.location; 

  const query = `
      SELECT pp.price 
      FROM product_prices pp
      JOIN locations l ON pp.location_id = l.id
      WHERE pp.product_id = ? AND l.name = ?
  `;

  db.query(query, [productId, userLocation], (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      if (results.length > 0) {
          res.json({ price: results[0].price });
      } else {
          res.status(404).json({ error: 'Price not found for this location' });
      }
  });
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
