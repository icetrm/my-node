const onConnection = (io, socket) => {
    console.log(`[Connection]: ${socket.id}`)
    console.log(socket.rooms);

    socket.on("disconnecting", (reason) => {
        console.log(`[Disconnecting]: ${socket.id} ${reason}`)
        // for (const room of socket.rooms) {
        //     if (room !== socket.id) {
        //         socket.to(room).emit("user has left", socket.id);
        //     }
        // }
    });
    // socket.on('new user', (data) => {
    //     console.log(data)
    //     io.emit('new user', data);
    // })
};

module.exports = {
    onConnection
}