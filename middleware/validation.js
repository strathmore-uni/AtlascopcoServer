const Joi = require("joi");

// Validation schema for user registration
const validateRegistration = (req, res, next) => {
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

// Validation schema for login
const validateLogin = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details });
  }
  next();
};

// Validation schema for product creation
const validateProduct = (req, res, next) => {
  const schema = Joi.object({
    partnumber: Joi.string().required(),
    description: Joi.string().required(),
    image: Joi.string().optional(),
    thumb1: Joi.string().optional(),
    thumb2: Joi.string().optional(),
    prices: Joi.array().items(
      Joi.object({
        country_code: Joi.string().required(),
        price: Joi.number().required(),
        stock_quantity: Joi.number().optional(),
      })
    ).required(),
    mainCategory: Joi.string().required(),
    subCategory: Joi.string().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details });
  }
  next();
};

// Validation schema for order creation
const validateOrder = (req, res, next) => {
  const schema = Joi.object({
    formData: Joi.object({
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
      country: Joi.string().required(),
    }).required(),
    cartItems: Joi.array().items(
      Joi.object({
        partnumber: Joi.string().required(),
        quantity: Joi.number().required(),
        description: Joi.string().required(),
        price: Joi.number().required(),
      })
    ).required(),
    orderNumber: Joi.string().required(),
    newPrice: Joi.number().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details });
  }
  next();
};

module.exports = {
  validateRegistration,
  validateLogin,
  validateProduct,
  validateOrder,
}; 