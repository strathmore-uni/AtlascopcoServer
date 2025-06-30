const express = require("express");
const router = express.Router();
const pool = require("../config/database");
const { getAdminPermissions } = require("../middleware/auth");
const { validateProduct } = require("../middleware/validation");

// Get all products for a user (filtered by country)
router.get("/", async (req, res) => {
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

// Get products by category
router.get("/category/:category?", async (req, res) => {
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

// Get product by ID
router.get("/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10);

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
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product details:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get product specifications
router.get("/:id/specifications", async (req, res) => {
  const productId = parseInt(req.params.id, 10);

  if (isNaN(productId)) {
    return res.status(400).json({ message: 'Invalid product ID' });
  }

  try {
    const [specifications] = await pool.query(
      `SELECT spec_key, spec_value
       FROM product_specifications
       WHERE product_id = ?`,
      [productId]
    );

    if (specifications.length === 0) {
      return res.status(404).json({ message: 'Product specifications not found' });
    }

    res.json(specifications);
  } catch (error) {
    console.error('Error fetching product specifications:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Search products
router.get("/search", async (req, res) => {
  const searchTerm = req.query.term || "";
  const category = req.query.category || "";
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

    if (category) {
      query += " AND (p.mainCategory = ? OR p.subCategory = ?)";
      queryParams.push(category, category);
    }

    const [results] = await pool.query(query, queryParams);
    res.json(results);
  } catch (err) {
    console.error("Error executing search query:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Get product by part number
router.get("/partnumber/:partnumber", async (req, res) => {
  const { partnumber } = req.params;
  const userEmail = req.query.email;

  try {
    if (!userEmail) {
      return res.status(400).json({ message: "Email is required" });
    }

    const query = `
      SELECT p.partnumber, p.Description, p.image, pp.price AS Price
      FROM fulldata p
      JOIN product_prices pp ON p.id = pp.product_id
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

// Get related products
router.get("/:productId/related", async (req, res) => {
  const { productId } = req.params;

  try {
    const [currentProduct] = await pool.query('SELECT mainCategory, subCategory FROM fulldata WHERE id = ?', [productId]);
    if (currentProduct.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    const { mainCategory, subCategory } = currentProduct[0];
    
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

// Admin: Get all products for management
router.get("/admin/all", async (req, res) => {
  try {
    const productsQuery = `
      SELECT p.id, p.partnumber, p.Description, p.mainCategory, p.subCategory, p.image, p.thumb1, p.thumb2
      FROM fulldata p
    `;
    const [products] = await pool.query(productsQuery);
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get product details for editing
router.get("/admin/:id", async (req, res) => {
  const productId = req.params.id;
  const adminEmail = req.query.email;

  if (!adminEmail) {
    return res.status(401).json({ error: "Unauthorized: No email provided" });
  }

  try {
    const countryQuery = "SELECT country, role FROM registration WHERE email = ?";
    const [countryResult] = await pool.query(countryQuery, [adminEmail]);

    if (countryResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const { country: adminCountryCode, role: adminRole } = countryResult[0];

    const productQuery = `
      SELECT id, partnumber, Description, image, thumb1, thumb2, mainCategory, subCategory, detailedDescription
      FROM fulldata
      WHERE id = ?
    `;
    const [product] = await pool.query(productQuery, [productId]);

    if (product.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    const specificationsQuery = `
      SELECT spec_key, spec_value
      FROM product_specifications
      WHERE product_id = ?
    `;
    const [specifications] = await pool.query(specificationsQuery, [productId]);

    let pricesQuery = `
      SELECT country_code, price, stock_quantity
      FROM product_prices
      WHERE product_id = ?
    `;
    const queryParams = [productId];

    if (adminRole !== "superadmin") {
      pricesQuery += " AND country_code = ?";
      queryParams.push(adminCountryCode);
    }

    const [prices] = await pool.query(pricesQuery, queryParams);

    const descriptionsQuery = `
      SELECT description
      FROM product_descriptions
      WHERE product_id = ?
    `;
    const [descriptions] = await pool.query(descriptionsQuery, [productId]);

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

// Admin: Create new product
router.post("/admin", validateProduct, async (req, res) => {
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
  const userEmail = req.headers["user-email"];

  try {
    const permissions = await getAdminPermissions(userEmail);

    if (!permissions.create_permission) {
      return res.status(403).json({ error: "Permission denied: Cannot create products" });
    }

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

    const insertPricesQuery = "INSERT INTO product_prices (product_id, country_code, price, stock_quantity) VALUES ?";
    const priceValues = prices.map((price) => [
      productId,
      price.country_code,
      price.price,
      stock,
    ]);
    await pool.query(insertPricesQuery, [priceValues]);

    res.status(201).json({ message: "Product added successfully" });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Update product
router.put("/admin/:id", async (req, res) => {
  const productId = req.params.id;
  const {
    partnumber,
    Description,
    descriptions = [],
    specifications = [],
    image,
    thumb1,
    thumb2,
    mainCategory,
    subCategory,
    prices = [],
    email,
  } = req.body;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const adminPermissions = await getAdminPermissions(email);
    if (!adminPermissions || !adminPermissions.update_permission) {
      throw new Error("Permission denied");
    }

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

    if (Array.isArray(descriptions)) {
      await connection.query(`DELETE FROM product_descriptions WHERE product_id = ?`, [productId]);
      const insertDescriptionQuery = `INSERT INTO product_descriptions (product_id, description) VALUES (?, ?)`;
      for (const desc of descriptions) {
        await connection.query(insertDescriptionQuery, [productId, desc]);
      }
    }

    if (Array.isArray(specifications)) {
      await connection.query(`DELETE FROM product_specifications WHERE product_id = ?`, [productId]);
      const insertSpecificationQuery = `INSERT INTO product_specifications (product_id, spec_key, spec_value) VALUES (?, ?, ?)`;
      for (const spec of specifications) {
        await connection.query(insertSpecificationQuery, [productId, spec.spec_key, spec.spec_value]);
      }
    }

    if (Array.isArray(prices)) {
      await connection.query(`DELETE FROM product_prices WHERE product_id = ?`, [productId]);
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
    }

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

// Admin: Delete product
router.delete("/admin/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10);
  const { email } = req.body;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const adminPermissions = await getAdminPermissions(email);
    if (!adminPermissions || !adminPermissions.delete_permission) {
      throw new Error("Permission denied");
    }

    await connection.query("DELETE FROM product_prices WHERE product_id = ?", [productId]);
    await connection.query("DELETE FROM fulldata WHERE id = ?", [productId]);

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

// Get categories
router.get("/categories/all", async (req, res) => {
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

// Get product details by ID
router.get("/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10);

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
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product details:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get product specifications
router.get("/spec/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10);

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

// Get user's products (filtered by country)
router.get("/myproducts", async (req, res) => {
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

// Get related products
router.get("/related/:productId", async (req, res) => {
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

// Get product reviews
router.get("/reviews/:productId", async (req, res) => {
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

// Add product review
router.post("/reviews", async (req, res) => {
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

// Admin: Get all products for viewing
router.get("/admin/view", async (req, res) => {
  try {
    const productsQuery = `
      SELECT p.id, p.partnumber, p.Description, p.mainCategory, p.subCategory, p.image, p.thumb1, p.thumb2
      FROM fulldata p
    `;
    const [products] = await pool.query(productsQuery);
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get product details for editing
router.get("/admin/view/:id", async (req, res) => {
  const productId = req.params.id;
  const adminEmail = req.query.email;

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

// Admin: Update product
router.put("/admin/view/:id", async (req, res) => {
  const productId = req.params.id;
  const {
    partnumber,
    Description,
    descriptions = [],
    specifications = [],
    image,
    thumb1,
    thumb2,
    mainCategory,
    subCategory,
    prices = [],
    email,
  } = req.body;

  console.log(`Received PUT request for product ID: ${productId}`);

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Log the attempted update action
    const details = `Attempted to update product: partnumber=${partnumber}, Description=${Description}, image=${image}, thumb1=${thumb1}, thumb2=${thumb2}, mainCategory=${mainCategory}, subCategory=${subCategory}, prices=${JSON.stringify(prices)}`;
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
      await connection.query(auditLogQueryDenied, [productId, deniedDetails, email]);

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
    const successDetails = `Successfully updated product details: partnumber=${partnumber}, Description=${Description}, image=${image}, thumb1=${thumb1}, thumb2=${thumb2}, mainCategory=${mainCategory}, subCategory=${subCategory}, prices=${JSON.stringify(prices)}`;
    const auditLogQuerySuccess = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'update_successful', ?, ?)
    `;
    await connection.query(auditLogQuerySuccess, [productId, successDetails, email]);

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

// Admin: Delete product
router.delete("/admin/view/:id", async (req, res) => {
  const productId = parseInt(req.params.id, 10);
  const { email } = req.body;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Log the attempted delete action
    const attemptDetails = `Attempted to delete product with ID: ${productId}`;
    const auditLogAttemptQuery = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'attempted_delete', ?, ?)
    `;
    await connection.query(auditLogAttemptQuery, [productId, attemptDetails, email]);

    // Check admin permissions before proceeding
    const adminPermissions = await getAdminPermissions(email);
    console.log("Admin permissions:", adminPermissions);

    if (!adminPermissions || !adminPermissions.delete_permission) {
      // Log the failed attempt due to permission denial
      const deniedDetails = `Permission denied for user: ${email}`;
      const auditLogDeniedQuery = `
        INSERT INTO product_audit_log (product_id, action, details, changed_by)
        VALUES (?, 'delete_failed', ?, ?)
      `;
      await connection.query(auditLogDeniedQuery, [productId, deniedDetails, email]);

      throw new Error("Permission denied");
    }

    // Delete from product_prices table
    await connection.query("DELETE FROM product_prices WHERE product_id = ?", [productId]);

    // Delete from fulldata table
    await connection.query("DELETE FROM fulldata WHERE id = ?", [productId]);

    // Log the successful delete action
    const successDetails = `Successfully deleted product with ID: ${productId}`;
    const auditLogSuccessQuery = `
      INSERT INTO product_audit_log (product_id, action, details, changed_by)
      VALUES (?, 'delete_successful', ?, ?)
    `;
    await connection.query(auditLogSuccessQuery, [productId, successDetails, email]);

    await connection.commit();
    res.json({ message: "Product deleted successfully" });

    // Notify admin
    const notificationLogQuery = `
      INSERT INTO notifications (user_email, message, date)
      VALUES (?, ?, NOW())
    `;
    await connection.query(notificationLogQuery, [email, `Product ${productId} deleted`]);
  } catch (error) {
    await connection.rollback();
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product" });
  } finally {
    connection.release();
  }
});

// Admin: Add new product
router.post("/admin/new", async (req, res) => {
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
  const userEmail = req.headers["user-email"];

  try {
    const permissions = await getAdminPermissions(userEmail);

    if (!permissions.create_permission) {
      return res.status(403).json({ error: "Permission denied: Cannot create products" });
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
    const insertPricesQuery = "INSERT INTO product_prices (product_id, country_code, price, stock_quantity) VALUES ?";
    const priceValues = prices.map((price) => [
      productId,
      price.country_code,
      price.price,
      stock,
    ]);
    await pool.query(insertPricesQuery, [priceValues]);

    res.status(201).json({ message: "Product added successfully" });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Add products in batch
router.post("/admin/new/batch", async (req, res) => {
  const products = req.body.products;
  const userEmail = req.headers["user-email"];

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
      const productId = result.insertId;

      // Insert prices into product_prices table
      for (const price of prices) {
        const { country_code, price: priceValue, stock_quantity } = price;
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

// Admin: Get products near completion
router.get("/admin/near-completion", async (req, res) => {
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
      return res.status(404).json({ message: "No products near completion found" });
    }

    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products near completion:", error);
    res.status(500).json({ error: "Error fetching products near completion" });
  }
});

// Admin: Get product order count
router.get("/admin/order-count/:partnumber", async (req, res) => {
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

// Admin: Get most ordered products
router.get("/admin/most-ordered", async (req, res) => {
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

// Admin: Get product count
router.get("/admin/count", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT COUNT(*) AS count FROM fulldata");
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching product count:", error);
    res.status(500).json({ error: "Error fetching product count" });
  }
});

// Get sales data for a product
router.get("/sales-data/:productId", async (req, res) => {
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

module.exports = router; 