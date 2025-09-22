import mongoose from "mongoose";

const chatSchema = new mongoose.Schema({
  roomId: String,
  senderId: String,
  receiverId: String,
  message: String,
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Chat", chatSchema);
