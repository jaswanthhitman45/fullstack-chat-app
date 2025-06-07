import express from "express"
import dotenv from "dotenv"
import authRoutes from "./routes/auth.route.js"
import messageRoutes from "./routes/message.route.js"
import { connectDB } from "./lib/db.js";
import cookieParser from "cookie-parser"
import cors from "cors"
import { server, app } from "./lib/socket.js"
import path from "path";


dotenv.config()
const PORT = process.env.PORT
const __dirname = path.resolve();

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true,
}))
app.use("/api/auth", authRoutes)
app.use("/api/messages", messageRoutes)

if (process.env.NODE_ENV === "production") {
    app.use(express.static(path.join(__dirname, "../Frontend/vite-project/dist")));
   app.get('*splat', (req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/vite-project/dist/index.html'));
});
}

server.listen(PORT, () => {
    console.log("Server is running on port "+PORT);
    connectDB();
})