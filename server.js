import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import personRoutes from './routes/personRoutes.js';

dotenv.config();

const app = express();
app.use(express.json());

// Routes
app.use('/api/person', personRoutes);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Render provides PORT automatically
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

