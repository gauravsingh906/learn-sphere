import { configDotenv } from 'dotenv';
configDotenv({ path: './.env' });
import session from 'express-session';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import userRoutes from './routes/user.routes.js';
import courseRoutes from './routes/course.routes.js';
import passport from './utils/passport.js';

// import paymentRoutes from './routes/payment.routes.js';
import miscellaneousRoutes from './routes/miscellaneous.routes.js';
import express from 'express';
import connectToDb from './config/db.config.js';
import errorMiddleware from './middleware/error.middleware.js';

const app = express();

// middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('dev'));
console.log(process.env.FRONTEND_URL, "frontend url");
app.use(cors({ origin: [process.env.FRONTEND_URL], credentials: true }));
app.use(passport.initialize());
app.use(passport.session());

app.use('/api/v1/user', userRoutes);
app.use('/api/v1/courses', courseRoutes);
// app.use('/api/v1/payments', paymentRoutes);
app.use('/api/v1/', miscellaneousRoutes);


app.all('*', (req, res) => {
    res.status(404).send('OOPS!! 404 page not found');
})

app.use(errorMiddleware);

// db init
connectToDb();

export default app;