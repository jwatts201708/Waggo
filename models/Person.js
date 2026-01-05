import mongoose from "mongoose";

const PersonSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    age: { type: Number, required: false }
  },
  { timestamps: true }
);

export default mongoose.model("Person", PersonSchema);

