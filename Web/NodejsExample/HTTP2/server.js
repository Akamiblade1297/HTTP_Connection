const http2 = require('http2');

const server = http2.createServer();
server.on('stream', (stream, headers) => {
  stream.respond({
    ':status': 200,
    'content-type': 'text/plain'
  });
  stream.end('Hello, H2C World! Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!Hello, H2C World!');
});

server.listen(3000, () => {
  console.log('H2C server running on http://localhost:3000');
});
