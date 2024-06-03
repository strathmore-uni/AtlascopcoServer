// MySQL connection

{/**
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '10028mike.',
  database: 'atlascopco'

  
    host:'ultra-mediator-423907-a4:us-central1:atlascopco',
  user:'atlascopco_admin',
  password:'10028mike.',
  database:'AtlasCopco',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,



  username: process.env.DB_USERNAME,
password: process.env.DB_PASSWORD,
database: process.env.DATABASE,
port: process.env.DB_PORT,
host:process.env.DB_HOST
});
 
connection.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
  } else {
    console.log('Connected to MySQL');
  }
});


*/}




app.get('/api/data', async (req, res) => {
  try {
      const connection = await pool.getConnection();
      const [rows] = await connection.query('SELECT * FROM products');
      connection.release();
      res.json(rows);
  } catch (error) {
      console.error(error);
      res.status(500).send('Error fetching data');
  }
});


app.get('/', (req, res) => {
  res.send('Hello World!');
});





//API REQUESTS
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









//////////////////////////API REQUESTS//////////////////////////////


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

