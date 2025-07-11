require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL || 'mongodb+srv://hephzibarsamuel:sHFaJEdlFlDCaQwb@contact-gain.cbtkalw.mongodb.net/?retryWrites=true&w=majority&appName=Contact-Gain', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'e24c9bf7d58a4c3e9f1a6b8c7d3e2f4981a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  },
  store: require('connect-mongo').create({ 
    mongoUrl: process.env.MONGO_URL,
    ttl: 24 * 60 * 60 
  })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  profile: {
    name: String,
    phone: String,
    bio: { type: String, default: 'No bio yet' },
    profilePic: { type: String, default: '/images/default-avatar.png' }
  },
  isAdmin: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sessionId: { type: String, unique: true, required: true },
  groupName: { type: String, required: true },
  whatsappLink: { type: String },
  timer: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  downloadCount: { type: Number, default: 0 },
  contactCount: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'expired', 'deleted'], default: 'active' }
});

const contactSchema = new mongoose.Schema({
  sessionId: { type: String, required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const downloadSchema = new mongoose.Schema({
  sessionId: { type: String, required: true },
  status: { type: String, enum: ['success', 'failed'], required: true },
  timestamp: { type: Date, default: Date.now },
  error: { type: String }
});

const messageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'image', 'ai'], default: 'text' },
  aiModel: String,
  deleted: { type: Boolean, default: false },
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  edited: { type: Boolean, default: false },
  replies: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }],
  pinned: { type: Boolean, default: false },
  isPrivate: { type: Boolean, default: false },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, default: 'Community' },
  description: { type: String, default: 'Official community group' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  profilePic: { type: String, default: '/images/group-avatar.png' }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);

// Passport Configuration
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    if (user.status === 'banned') return done(null, false, { message: 'User is banned.' });
    if (user.status === 'suspended') return done(null, false, { message: 'User is suspended.' });
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return done(null, false, { message: 'Incorrect password.' });
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) return next();
  res.redirect('/admin/login');
};

// Socket.IO Logic
io.on('connection', (socket) => {
  console.log('User connected');
  
  socket.on('join', async (userId) => {
    socket.userId = userId;
    socket.join(userId);
    
    // Update last seen
    await User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
    
    // Add user to community group
    let group = await Group.findOne({ name: 'Community' });
    if (!group) {
      group = new Group({ 
        name: 'Community',
        members: [userId],
        admins: [userId]
      });
      await group.save();
    } else if (!group.members.includes(userId)) {
      group.members.push(userId);
      await group.save();
    }
    
    socket.emit('user-status', { userId, online: true });
  });

  socket.on('chat-message', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user || user.status !== 'active') return;
      
      const newMessage = new Message({
        userId: data.userId,
        content: data.content,
        isPrivate: data.isPrivate,
        recipient: data.recipient
      });
      
      await newMessage.save();
      
      if (data.isPrivate && data.recipient) {
        io.to(data.recipient).emit('private-message', {
          ...data,
          user: { id: user._id, username: user.username, profile: user.profile }
        });
        socket.emit('private-message', {
          ...data,
          user: { id: user._id, username: user.username, profile: user.profile }
        });
      } else {
        io.emit('chat-message', {
          ...data,
          user: { id: user._id, username: user.username, profile: user.profile }
        });
      }
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('typing', (data) => {
    if (data.isPrivate && data.recipient) {
      socket.to(data.recipient).emit('typing-private', data);
    } else {
      socket.broadcast.emit('typing', data);
    }
  });

  socket.on('ai-request', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user) return;
      
      const modelMap = {
        gpt: 'https://apis.davidcyriltech.my.id/ai/chatbot?query=',
        llama: 'https://apis.davidcyriltech.my.id/ai/llama3?text=',
        gemini: 'https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=',
        // Add other models
      };
      
      const apiUrl = modelMap[data.model] + encodeURIComponent(data.query);
      const response = await axios.get(apiUrl);
      
      let aiResponse = '';
      if (data.model === 'gpt') aiResponse = response.data.result;
      else if (data.model === 'gemini') aiResponse = response.data.result;
      else aiResponse = response.data.response || response.data.message;
      
      // Format response
      const formattedResponse = formatAIResponse(aiResponse, data.model);
      
      const aiMessage = new Message({
        userId: data.userId,
        content: formattedResponse,
        type: 'ai',
        aiModel: data.model
      });
      
      await aiMessage.save();
      
      io.emit('ai-response', {
        userId: data.userId,
        content: formattedResponse,
        messageId: aiMessage._id
      });
    } catch (err) {
      console.error('AI request error:', err);
      socket.emit('ai-error', { error: 'Failed to get AI response' });
    }
  });

  socket.on('disconnect', async () => {
    console.log('User disconnected');
    if (socket.userId) {
      await User.findByIdAndUpdate(socket.userId, { lastSeen: Date.now() });
      socket.broadcast.emit('user-status', { userId: socket.userId, online: false });
    }
  });
});

function formatAIResponse(response, model) {
  const now = new Date();
  return `
    <div class="ai-response">
      <div class="ai-header">
        <i class="fas fa-robot"></i>
        <span>AI Assistant (${model.toUpperCase()}) - Powered by Contact Gain</span>
      </div>
      <div class="ai-content">${response}</div>
      <div class="ai-footer">
        <span>Response generated at ${now.toLocaleTimeString()}</span>
      </div>
    </div>
  `;
}

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login', { error: req.flash('error') }));
app.get('/signup', (req, res) => res.render('signup', { error: req.flash('error') }));
app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    let group = await Group.findOne({ name: 'Community' });
    if (!group) {
      group = new Group({ 
        name: 'Community',
        members: [req.user._id],
        admins: [req.user._id]
      });
      await group.save();
    }
    
    const messages = await Message.find({ isPrivate: false })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('userId', 'username profile isAdmin');
    
    const onlineUsers = await User.find({ 
      lastSeen: { $gt: new Date(Date.now() - 5*60*1000) }
    });
    
    res.render('chat', { 
      user: req.user, 
      group,
      messages: messages.reverse(),
      onlineUsers 
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/terminal', isAuthenticated, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
    const totalContacts = await Contact.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
    const totalSessions = sessions.length;
    const activeSessions = sessions.filter(s => s.status === 'active').length;
    const totalDownloads = await Download.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
    const avgContacts = totalSessions > 0 ? (totalContacts / totalSessions).toFixed(1) : 0;

    res.render('terminal', { 
      user: req.user, 
      sessions,
      stats: {
        totalContacts,
        totalSessions: activeSessions,
        avgContacts,
        totalDownloads
      }
    });
  } catch (err) {
    console.error('Terminal error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalSessions = await Session.countDocuments();
    const activeSessions = await Session.countDocuments({ status: 'active' });
    const totalDownloads = await Download.countDocuments();
    const users = await User.find();

    res.render('admin', {
      stats: { totalUsers, totalSessions, activeSessions, totalDownloads },
      users
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const profileUser = await User.findById(req.params.userId);
    if (!profileUser) return res.status(404).send('User not found');
    
    res.render('profile', { 
      currentUser: req.user,
      profileUser 
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  try {
    const recipient = await User.findById(req.params.userId);
    if (!recipient) return res.status(404).send('User not found');
    
    const messages = await Message.find({
      $or: [
        { userId: req.user.id, recipient: recipient._id, isPrivate: true },
        { userId: recipient._id, recipient: req.user.id, isPrivate: true }
      ]
    })
    .sort({ createdAt: 1 })
    .populate('userId', 'username profile isAdmin');
    
    res.render('private-chat', { 
      currentUser: req.user,
      recipient,
      messages
    });
  } catch (err) {
    console.error('Private chat error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/signup', async (req, res) => {
  try {
    if (req.body.password !== req.body.confirmPassword) {
      req.flash('error', 'Passwords do not match');
      return res.redirect('/signup');
    }
    
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) {
      req.flash('error', 'Username already exists');
      return res.redirect('/signup');
    }
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ 
      username: req.body.username, 
      password: hashedPassword,
      profile: {
        name: req.body.name || req.body.username
      }
    });
    
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    req.flash('error', 'User creation failed');
    res.redirect('/signup');
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/terminal',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.post('/admin/login', (req, res) => {
  if (req.body.username === process.env.ADMIN_USERNAME && 
      req.body.password === process.env.ADMIN_PASSWORD) {
    // Set admin session
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('admin-login', { error: 'Invalid credentials' });
  }
});

app.post('/create-session', isAuthenticated, async (req, res) => {
  try {
    const { groupName, timer, whatsappLink } = req.body;
    const sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
    const expiresAt = new Date(Date.now() + parseInt(timer) * 60 * 1000);
    
    const session = new Session({
      userId: req.user._id, 
      sessionId, 
      groupName, 
      whatsappLink, 
      timer, 
      expiresAt
    });
    
    await session.save();
    const sessionLink = `${req.protocol}://${req.get('host')}/session/${sessionId}`;
    res.json({ sessionLink });
  } catch (err) {
    console.error('Session creation error:', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// Admin user management
app.post('/admin/suspend-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'suspended' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Suspend user error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/admin/unsuspend-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Unsuspend user error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/admin/ban-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'banned' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Ban user error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/admin/unban-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Unban user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
