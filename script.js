const jwt = require('jsonwebtoken');
const crypto = require('crypto');


const encryptionKey = '12345678901234567890123456789012'; 
const iv = crypto.randomBytes(16); 


const encrypt = (payload) => {
 
  const token = jwt.sign(payload, 'your_secret_key');

 
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    encryptedToken: encrypted,
    iv: iv.toString('hex'),  
  };
};


const decrypt = (encryptedData) => {
  const { encryptedToken, iv } = encryptedData; 
  const ivBuffer = Buffer.from(iv, 'hex'); 

  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), ivBuffer);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  try {
    const decodedToken = jwt.verify(decrypted, 'your_secret_key');
    return decodedToken;
  } catch (err) {
    console.error('Failed to verify token:', err.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt,
};
