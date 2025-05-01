import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});