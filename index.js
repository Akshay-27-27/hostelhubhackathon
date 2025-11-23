const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// Proper CORS for frontend (127.0.0.1:5500)
app.use(cors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// MongoDB connection with error handling
mongoose.connect(`mongodb+srv://akshay:akshay123@cluster0.mnvc2oq.mongodb.net/hackathon`, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Complaint Schema
const complaintSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, default: 'Open' },
  priority: { type: String, default: 'Low' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assignedTo: String
}, { timestamps: true });
const Complaint = mongoose.model('Complaint', complaintSchema);

// JWT Middleware
function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access Denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid Token' });
  }
}

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log(email, password);
    
    // Validation
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'Registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid password' });
    
    const token = jwt.sign(
      { _id: user._id, role: user.role }, 
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    res.json({ token, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Complaint
app.post('/api/complaints', auth, async (req, res) => {
  try {
    const complaint = new Complaint({ 
      ...req.body, 
      createdBy: req.user._id 
    });
    await complaint.save();
    res.status(201).json(complaint);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Complaints
app.get('/api/complaints', auth, async (req, res) => {
  try {
    const complaints = await Complaint.find().populate('createdBy', 'email');
    res.json(complaints);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Complaint Status (Admin)
app.put('/api/complaints/:id/status', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const complaint = await Complaint.findByIdAndUpdate(
      req.params.id, 
      { status: req.body.status }, 
      { new: true }
    );
    
    if (!complaint) {
      return res.status(404).json({ error: 'Complaint not found' });
    }
    
    res.json(complaint);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Analytics
app.get('/api/analytics', auth, async (req, res) => {
  try {
    const statuses = ['Open', 'In Progress', 'Resolved'];
    const data = await Promise.all(
      statuses.map(async status => {
        return await Complaint.countDocuments({ status });
      })
    );
    res.json({ labels: statuses, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Advanced Analytics: Most common issues & average resolution time
app.get('/api/analytics/advanced', auth, async (req, res) => {
  try {
    // Most common issues (group by title)
    const commonIssues = await Complaint.aggregate([
      { 
        $group: { 
          _id: "$title",
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Average resolution time (only for resolved complaints)
    const resolutionTime = await Complaint.aggregate([
      {
        $match: { status: "Resolved" }
      },
      {
        $project: {
          createdAt: 1,
          updatedAt: 1,
          resolutionHours: {
            $divide: [
              { $subtract: ["$updatedAt", "$createdAt"] },
              1000 * 60 * 60 // convert ms → hours
            ]
          }
        }
      },
      {
        $group: {
          _id: null,
          averageResolutionHours: { $avg: "$resolutionHours" }
        }
      }
    ]);

    res.json({
      mostCommonIssues: commonIssues,
      averageResolutionTimeHours: resolutionTime[0]?.averageResolutionHours || 0
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Analytics calculation error" });
  }
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));