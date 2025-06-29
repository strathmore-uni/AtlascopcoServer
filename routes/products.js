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

module.exports = router; 