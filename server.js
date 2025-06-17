const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

const cookieParser = require('cookie-parser');

const database = require('./config/database');

const router = require('./routes/authRoutes');

dotenv.config();

const app = express();

const ORIGIN = process.env.ORIGIN;

app.use(cors({
    origin: ORIGIN,
    credentials: true
}));
app.use(express.json());

app.use(cookieParser());

app.use('/uploads', express.static('uploads'));

const port = process.env.PORT || 5000;

database();

app.use("/api", router);


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});