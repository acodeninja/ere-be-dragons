const express = require('express');
const bodyParser = require('body-parser')
const winston = require('winston');

const port = process.env["PORT"] || 3000;
const app = express();

const logger = winston.createLogger({
  transports: [new winston.transports.Console()],
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use((req, res, next) => {
  const loggedObject = {};
  const loggedRequestFields = ['url', 'method', 'httpVersion', 'originalUrl', 'query'];
  const loggedResponseFields = ['statusCode'];

  loggedRequestFields.forEach(f => {
    loggedObject[f] = req[f];
  });
  loggedResponseFields.forEach(f => {
    loggedObject[f] = req[f];
  });

  logger.info(loggedObject);

  next();
});

const formPage = `
<!doctype html>
<html lang="en">
<body>
<a href="/search">Search</a>
<form method="post" action="/">
  <label for="words">Enter some words</label>
  <input name="words" id="words" />
  <button type="submit">Submit</button>
</form>
</body>
</html>
`;

const formInputs = [];

app.all('/', (req, res) => {
  if (req.body["words"]) formInputs.push(req.body["words"]);
  res.send(`${formPage}<ul>${formInputs.map(i => `<li>${i}</li>`).join('\n')}</ul>`);
});

const searchPage = `
<!doctype html>
<html lang="en">
<body>
<form action="/search">
  <label for="q">Search</label>
  <input name="q" id="q" />
  <button type="submit">Submit</button>
</form>
</body>
</html>
`;

app.all('/search', (req, res) => {
  res.send(`${searchPage}<p>You searched for: ${req.query['q']}</p>`);
});

app.listen(port, () => {
  logger.info({listening: port});
});
