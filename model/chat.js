// // model/chat.js
// import mongoose from "mongoose";

// const chatSchema = new mongoose.Schema(
//   {
//     senderId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "User",
//       required: true
//     },
//     receiverId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "User",
//       required: true
//     },
//     message: {
//       type: String,
//       required: true
//     }
//   },
//   { timestamps: true }
// );

// export default mongoose.model("Chat", chatSchema);
// model/chat.js
import mongoose from "mongoose";

const chatSchema = new mongoose.Schema(
  {
    senderPhone: {
      type: String,
      required: true
    },
    receiverPhone: {
      type: String,
      required: true
    },
    message: {
      type: String,
      required: true
    },
    isRead: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);

export default mongoose.model("Chat", chatSchema);

