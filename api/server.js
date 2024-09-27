const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRouter = require('./auth/auth-router.js');
const usersRouter = require('./users/users-router.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use(cookieParser());
server.use('/api/auth', authRouter);
server.use('/api/users', usersRouter);

server.use((err, req, res, next) => {
	// eslint-disable-line
	res.status(500).json({
		message: err.message,
		stack: err.stack
	});
});

module.exports = server;
