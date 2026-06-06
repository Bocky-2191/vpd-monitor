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
    const { accessId, secret, token, deviceId, region } = JSON.parse(event.body || '{}');
    if (!accessId || !secret || !token || !deviceId) throw new Error('Faltan parámetros');

    const t = Date.now().toString();
    const nonce = '';
    const method = 'GET';
    const path = '/v1.0/devices/' + deviceId + '/status';
    const contentHash = sha256('');

    // Tuya v1.0 device signature: includes access_token
    const strToSign = [method, contentHash, '', path].join('\n');
    const signStr = accessId + token + t + nonce + strToSign;
    const sign = hmacSHA256(secret, signStr).toUpperCase();

    const url = getBaseUrl(region) + path;
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'client_id': accessId,
        'access_token': token,
        'sign': sign,
        't': t,
        'sign_method': 'HMAC-SHA256',
        'nonce': nonce,
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
