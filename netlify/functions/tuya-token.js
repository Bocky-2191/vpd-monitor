const crypto = require('crypto');

function sha256(message) {
  return crypto.createHash('sha256').update(message).digest('hex');
}

function hmacSHA256(key, message) {
  return crypto.createHmac('sha256', key).update(message).digest('hex').toUpperCase();
}

function getBaseUrl(region) {
  const regions = {
    us: 'openapi.tuyaus.com',
    eu: 'openapi.tuyaeu.com',
    in: 'openapi.tuyain.com',
    cn: 'openapi.tuyacn.com'
  };
  return 'https://' + (regions[region] || regions.us);
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const { accessId, secret, region } = JSON.parse(event.body || '{}');
    if (!accessId || !secret) throw new Error('Faltan credenciales');

    const t = Date.now().toString();
    const contentHash = sha256('');
    const strToSign = accessId + t + contentHash;
    const sign = hmacSHA256(secret, strToSign).toUpperCase();

    const url = getBaseUrl(region) + '/v1.0/token?grant_type=1';
    const resp = await fetch(url, {
      headers: {
        'client_id': accessId,
        'sign': sign,
        't': t,
        'sign_method': 'HMAC-SHA256',
        'Content-Type': 'application/json'
      }
    });

    const data = await resp.json();
    return { statusCode: 200, headers, body: JSON.stringify(data) };

  } catch (err) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ success: false, msg: err.message })
    };
  }
};
