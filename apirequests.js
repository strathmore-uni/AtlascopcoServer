app.get('/api/fulldata', (req, res) => {
    connection.query('SELECT * FROM fulldata WHERE mainCategory LIKE ?', ['%filterelement%'], (err, results) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json(results);
      }
    });
  });

  app.get('/api/servkit', (req, res) => {
    connection.query('SELECT * FROM servkit', (err, results) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json(results);
      }
    });
  });