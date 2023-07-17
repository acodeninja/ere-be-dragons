const express = require('express');
const bodyParser = require('body-parser')
const winston = require('winston');
const {createHash} = require("crypto");

try {
  const mod = `test-${Date.now()}`;
  require(mod);
} catch (e) {

}

const startTimeHash = createHash("md5").update(new Date().toString()).digest("hex");

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

const formPage = `<!doctype html>
<html lang="en">
<body>
<a href="/search">Search</a>
<form method="post" action="/">
  <label for="words">Enter some words</label>
  <input name="words" id="words" />
  <button type="submit">Submit</button>
</form>
${startTimeHash}
</body>
</html>
`;

const formInputs = [];

app.all('/', (req, res) => {
  if (req.body["words"]) formInputs.push(req.body["words"]);
  if (req.body["words"]?.match(/`(?:\\[\s\S]|\${(?:[^{}]|{(?:[^{}]|{[^}]*})*})*}|(?!\${)[^\\`])*`/g))
    logger.info('Regex match failed');

  res.send(`${formPage}<ul>${formInputs.map(i => `<li>${i}</li>`).join('\n')}</ul>`);
});

const searchPage = `<!doctype html>
<html lang="en">
<body>
<form action="/search">
  <label for="q">Search</label>
  <input name="q" id="q" />
  <button type="submit">Submit</button>
</form>
${startTimeHash}
</body>
</html>
`;

app.all('/search', (req, res) => {
  res.send(`${searchPage}<p>You searched for: ${req.query['q']}</p>`);
});

app.listen(port, () => {
  logger.info({listening: port});
});
