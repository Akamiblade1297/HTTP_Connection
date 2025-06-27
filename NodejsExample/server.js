const express = require("express");
const app = express();
const port = 3000;

app.use(express.text());

app.post('/', (req,res) => {
    console.log(`Got a request: ${req.body}`);
    res.send("Hello, from server!");
});

app.get('/', (req,res) => {
    res.send("Hello, from server!");
});

app.listen(port, () => {
    console.log(`Server is listening on localhost:${port}`);
});
