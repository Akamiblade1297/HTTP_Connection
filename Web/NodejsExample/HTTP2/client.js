const http2 = require('http2');

const client = http2.connect('http://localhost:3000', {
    settings: {
        initialWindowSize: 200
    }
});
const req = client.request({ ':path': '/' });

req.on('response', (headers) => {
  console.log('Response headers:', headers);
});

req.on('data', (chunk) => {
  console.log('Received:', chunk.toString());
});

req.on('end', () => {
  console.log('Request complete');
  client.close();
});

req.end();
