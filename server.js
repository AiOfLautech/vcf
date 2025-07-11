require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const axios = require('axios');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL || 'mongodb+srv://hephzibarsamuel:sHFaJEdlFlDCaQwb@contact-gain.cbtkalw.mongodb.net/?retryWrites=true&w=majority&appName=Contact-Gain', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('MongoDB connected successfully');
  })
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
    secure: process.env.LINODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  isAdmin: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  profile: {
    name: String,
    phone: String,
    bio: String,
    profilePic: String
  }
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
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now },
  deleted: { type: Boolean, default: false },
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  edited: { type: Boolean, default: false },
  repliedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  isPrivate: { type: Boolean, default: false },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  profilePic: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);

// Create default group
async function createDefaultGroup() {
  const group = await Group.findOne({ name: 'Contact Gain Community' });
  if (!group) {
    const newGroup = new Group({
      name: 'Contact Gain Community',
      description: 'Official community group for Contact Gain users',
      members: []
    });
    await newGroup.save();
    console.log('Default group created');
  }
}

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

// Authentication Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  if (req.accepts('json')) return res.status(401).json({ error: 'Authentication required' });
  res.redirect('/login');
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('A user connected');
  
  // Join user to their room
  socket.on('join', (userId) => {
    socket.join(userId);
    User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
  });
  
  // Handle chat messages
  socket.on('chat-message', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user) return;
      
      const message = new Message({
        userId: data.userId,
        content: data.content,
        isPrivate: data.isPrivate,
        recipient: data.recipient
      });
      
      await message.save();
      
      if (data.isPrivate) {
        io.to(data.recipient).to(data.userId).emit('private-message', {
          user: {
            id: user._id,
            username: user.username,
            isAdmin: user.isAdmin,
            profile: user.profile
          },
          content: data.content,
          createdAt: new Date()
        });
      } else {
        io.emit('chat-message', {
          user: {
            id: user._id,
            username: user.username,
            isAdmin: user.isAdmin,
            profile: user.profile
          },
          content: data.content,
          createdAt: new Date()
        });
      }
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });
  
  // Handle AI requests
  socket.on('ai-request', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user) return;
      
      const aiModels = {
        gpt: 'https://apis.davidcyriltech.my.id/ai/chatbot?query=',
        llama: 'https://apis.davidcyriltech.my.id/ai/llama3?text=',
        deepseek: 'https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=',
        gemini: 'https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q='
      };
      
      const url = aiModels[data.model] + encodeURIComponent(data.query);
      const response = await axios.get(url);
      
      let aiResponse = '';
      if (data.model === 'gpt') {
        aiResponse = response.data.result;
      } else if (data.model === 'llama') {
        aiResponse = response.data.message;
      } else if (data.model === 'deepseek') {
        aiResponse = response.data.response;
      } else if (data.model === 'gemini') {
        aiResponse = response.data.result;
      }
      
      // Format AI response
      const formattedResponse = `
        <div class="ai-response">
          <div class="ai-header">
            <i class="fas fa-robot"></i> AI Assistant
          </div>
          <div class="ai-content">
            <pre>${aiResponse}</pre>
          </div>
          <div class="ai-footer">
            Powered by Contact Gain
          </div>
        </div>
      `;
      
      socket.emit('ai-response', {
        content: formattedResponse
      });
    } catch (err) {
      console.error('AI request error:', err);
      socket.emit('ai-response', {
        content: 'Error processing your request. Please try again.'
      });
    }
  });
  
  // Typing indicator
  socket.on('typing', (data) => {
    socket.broadcast.emit('typing', data);
  });
  
  // Disconnect
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

// Terminal (Dashboard)
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

// Admin Dashboard
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalSessions = await Session.countDocuments();
    const activeSessions = await Session.countDocuments({ status: 'active' });
    const totalDownloads = await Download.countDocuments();
    const succeededDownloads = await Download.countDocuments({ status: 'success' });
    const failedDownloads = await Download.countDocuments({ status: 'failed' });
    const expiredOrDeletedSessions = await Session.countDocuments({ $or: [{ status: 'expired' }, { status: 'deleted' }] });
    const totalContacts = await Contact.countDocuments();
    const sessionsWithWhatsapp = await Session.countDocuments({ whatsappLink: { $ne: null } });
    const sessions = await Session.find().sort({ createdAt: -1 });
    const recentSessions = await Session.find().sort({ createdAt: -1 }).limit(5).populate('userId');
    const recentDownloads = await Download.find().sort({ timestamp: -1 }).limit(5);
    const users = await User.find();

    res.render('admin', {
      stats: {
        totalUsers, totalSessions, activeSessions, totalDownloads,
        succeededDownloads, failedDownloads, expiredOrDeletedSessions,
        totalContacts, sessionsWithWhatsapp
      },
      recentSessions,
      recentDownloads,
      users,
      sessions
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).send('Internal server error');
  }
});

// Community Chat
app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    const group = await Group.findOne({ name: 'Contact Gain Community' });
    if (!group) {
      await createDefaultGroup();
      return res.redirect('/chat');
    }
    
    // Add user to group if not already a member
    if (!group.members.includes(req.user._id)) {
      group.members.push(req.user._id);
      await group.save();
    }
    
    const messages = await Message.find({ isPrivate: false })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('userId')
      .populate('repliedTo');
      
    const onlineUsers = await User.find({ 
      lastSeen: { $gt: Date.now() - 300000 } 
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

// User Profile
app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const profileUser = await User.findById(req.params.userId);
    if (!profileUser) {
      return res.status(404).send('User not found');
    }
    
    res.render('profile', {
      currentUser: req.user,
      profileUser
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal server error');
  }
});

// Private Chat
app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  try {
    const recipient = await User.findById(req.params.userId);
    if (!recipient) {
      return res.status(404).send('User not found');
    }
    
    const messages = await Message.find({
      $or: [
        { userId: req.user._id, recipient: recipient._id },
        { userId: recipient._id, recipient: req.user._id }
      ]
    })
    .sort({ createdAt: 1 })
    .populate('userId');
    
    res.render('private-chat', {
      user: req.user,
      recipient,
      messages
    });
  } catch (err) {
    console.error('Private chat error:', err);
    res.status(500).send('Internal server error');
  }
});

// Consolidated Session Route
app.get('/session/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).send('Session not found.');
    }
    // Check if session is expired and update status if necessary
    if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
      sessionData.status = 'expired';
      await sessionData.save();
    }
    // Calculate remaining time
    const msLeft = sessionData.expiresAt - Date.now();
    const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;

    // Get recommended sessions (last 5 active sessions excluding current)
    const recommendedSessions = await Session.find({ 
      sessionId: { $ne: sessionId },
      expiresAt: { $gt: new Date() },
      status: 'active'
    }).sort({ createdAt: -1 }).limit(5);

    res.render('session', {
      groupName: sessionData.groupName,
      sessionId: sessionData.sessionId,
      whatsappLink: sessionData.whatsappLink,
      totalSeconds,
      recommendedSessions
    });
  } catch (err) {
    console.error('Session error:', err);
    res.status(500).send('Internal server error.');
  }
});

// Delete Session from Terminal
app.post('/delete-session/:sessionId', isAuthenticated, async (req, res) => {
  try {
    const session = await Session.findOne({ sessionId: req.params.sessionId, userId: req.user._id });
    if (!session) {
      return res.status(404).send('Session not found');
    }
    await session.remove();
    res.redirect('/terminal');
  } catch (err) {
    console.error('Delete session error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Delete User
app.post('/admin/delete-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.userId);
    res.redirect('/admin');
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Delete Session
app.post('/admin/delete-session/:sessionId', isAdmin, async (req, res) => {
  try {
    await Session.findOneAndDelete({ sessionId: req.params.sessionId });
    res.redirect('/admin');
  } catch (err) {
    console.error('Delete session error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Suspend User
app.post('/admin/suspend-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'suspended' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Suspend user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Unsuspend User
app.post('/admin/unsuspend-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Unsuspend user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Ban User
app.post('/admin/ban-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'banned' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Ban user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Unban User
app.post('/admin/unban-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
    res.redirect('/admin');
  } catch (err) {
    console.error('Unban user error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Promote User
app.post('/admin/promote-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { isAdmin: true });
    res.redirect('/admin');
  } catch (err) {
    console.error('Promote user error:', err);
    res.status(500).send('Internal server error');
  }
});

// User Signup
app.post('/signup', async (req, res) => {
  try {
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) return res.render('signup', { error: 'Username already exists' });
    
    if (req.body.password !== req.body.confirmPassword) {
      return res.render('signup', { error: 'Passwords do not match' });
    }
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.render('signup', { error: 'User creation failed' });
  }
});

// User Login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: false
}));

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

// Admin Login
app.get('/admin/login', (req, res) => {
  res.render('admin-login');
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('admin-login', { error: 'Invalid credentials' });
  }
});

// Create Session
app.post('/create-session', isAuthenticated, async (req, res) => {
  const { groupName, timer, whatsappLink } = req.body;
  if (!groupName || !timer) return res.status(400).json({ error: 'Group name and timer are required.' });
  if (isNaN(timer) || timer <= 0 || timer > 1440) return res.status(400).json({ error: 'Timer must be a positive number up to 1440 minutes.' });
  const sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
  const now = Date.now();
  const expiresAt = new Date(now + parseInt(timer) * 60 * 1000);
  try {
    const session = new Session({
      userId: req.user._id, sessionId, groupName, whatsappLink, timer, expiresAt
    });
    await session.save();
    const sessionLink = `${req.protocol}://${req.get('host')}/session/${sessionId}`;
    res.json({ sessionLink });
  } catch (err) {
    console.error('Session creation error:', err);
    res.status(500).json({ error: 'Failed to create session.' });
  }
});

app.post('/session/:sessionId/contact', async (req, res) => {
  const { name, phone } = req.body;
  const { sessionId } = req.params;

  if (!name || !phone) {
    return res.status(400).json({ error: 'Name and phone are required.' });
  }

  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).json({ error: 'Session not found.' });
    }

    if (Date.now() > sessionData.expiresAt) {
      sessionData.status = 'expired';
      await sessionData.save();
      return res.status(400).json({ error: 'Session has ended.' });
    }

    const contact = new Contact({ sessionId, name, phone });
    await contact.save();

    // Update contact count
    sessionData.contactCount += 1;
    await sessionData.save();

    res.json({ success: true });
  } catch (err) {
    console.error('Contact error:', err);
    res.status(500).json({ error: 'Failed to add contact.' });
  }
});

app.get('/session/:sessionId/download', async (req, res) => {
  const { sessionId } = req.params;

  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).send('Session not found.');
    }

    // Update download count
    sessionData.downloadCount += 1;
    await sessionData.save();

    const contacts = await Contact.find({ sessionId });
    let vcfData = '';

    contacts.forEach(contact => {
      vcfData += `BEGIN:VCARD
VERSION:3.0
FN:${contact.name}
TEL;TYPE=CELL:${contact.phone}
END:VCARD
`;
    });

    const fileName = `${sessionData.groupName.replace(/[^a-z0-9]/gi, '_')}_${sessionId}.vcf`;

    // Record download
    const download = new Download({
      sessionId,
      status: 'success'
    });
    await download.save();

    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(vcfData || 'No contacts were added.');
  } catch (err) {
    console.error('Download error:', err);

    // Record failed download
    const download = new Download({
      sessionId,
      status: 'failed',
      error: err.message
    });
    await download.save();

    res.status(500).send('Internal server error.');
  }
});

// Start Server
mongoose.connection.once('open', () => {
  createDefaultGroup();
  const PORT = process.env.PORT || 3000;
  http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
