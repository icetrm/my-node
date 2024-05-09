const express = require('express');
const { Server } = require("socket.io");
// const { createAdapter } = require("@socket.io/redis-adapter");
const { onConnection } = require("./events/visiterMessageHandler");

const app = express()
const port = 8000
const httpServer = require('http').createServer(app);
// const io = require('socket.io')(httpServer);
const io = new Server(httpServer, {
    path: "/ws/",
    cors: {
        origin: '*',
    }
})

io.on('connection', (socket) => onConnection(io, socket));

httpServer.listen(port);