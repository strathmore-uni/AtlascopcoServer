// sendMail.js
const formData = require('form-data');
const Mailgun = require('mailgun-js');

// Initialize Mailgun with your API key and domain
const mg = Mailgun({
  apiKey: process.env.MAILGUN_API_KEY || '8a084751-b1b7f64c',
  domain: process.env.MAILGUN_DOMAIN || 'sandbox0fc496d3d1814de5acf633ecb99caace.mailgun.org'
});

const sendEmail = async (to, subject, text, html) => {
  const data = {
    from: 'Excited User <mikekariuki10028@gmail.com>',
    to,
    subject,
    text,
    html
  };

  try {
    const response = await mg.messages().send(data);
    console.log('Message sent:', response);
    return response;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

module.exports = sendEmail;
