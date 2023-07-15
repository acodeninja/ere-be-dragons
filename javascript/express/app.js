const express = require('express');
const winston = require('winston');

const port = process.env["PORT"] || 3000;
const app = express();

const logger = winston.createLogger({
  transports: [new winston.transports.Console()],
});

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

app.get('/', (req, res) => {
  res.send(`<form><input name="words" /></form><p>${req.query?.words}</p>`);
});

app.listen(port, () => {
  logger.info({listening: port});
});
