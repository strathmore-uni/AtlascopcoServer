const { OAuth2Client } = require('google-auth-library');

const client = new OAuth2Client(
  'CLIENT_ID_1'
);

try {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience:GOOGLE_CLIENT_ID,
  });
  const result = ticket.getPayload();
  return result.email;
} catch (error) {
  // google auth library failed, move on
}

try {
  const result = await firebaseClient
    .auth()
    .verifyIdToken(token);
  return result.email;
} catch (error) {
  // move on
}