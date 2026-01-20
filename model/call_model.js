const callSchema = new mongoose.Schema({
    callerPhone: String,
    receiverPhone: String,
    startedAt: Date,
    endedAt: Date,
    duration: Number,
    tokensUsed: Number
  });

  module.exports = mongoose.model('Call', callSchema);