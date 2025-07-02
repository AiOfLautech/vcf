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
const sharedSession = require('express-socket.io-session');

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL || 'mongodb+srv://hephzibarsamuel:sHFaJEdlFlDCaQwb@contact-gain.cbtkalw.mongodb.net/?retryWrites=true&w=majority&appName=Contact-Gain', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('MongoDB connected successfully');
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Session configuration
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'e24c9bf7d58a4c3e9f1a6b8c7d3e2f4981a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.LINODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
});

app.use(sessionMiddleware);

// Share session with Socket.IO
io.use(sharedSession(sessionMiddleware, {
  autoSave: true
}));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  online: { type: Boolean, default: false },
  profile: {
    phone: String,
    bio: String,
    picture: String
  },
  privateMessaging: { type: Boolean, default: true }
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
  content: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  group: { type: String, default: 'main' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date },
  deleted: { type: Boolean, default: false },
  deletedBy: { type: String, enum: ['user', 'admin'] },
  pinned: { type: Boolean, default: false },
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  profilePicture: String
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);

// Create default group if not exists
async function createDefaultGroup() {
  const defaultGroup = await Group.findOne({ name: 'Community' });
  if (!defaultGroup) {
    const newGroup = new Group({
      name: 'Community',
      description: 'Main community group for all users',
      members: []
    });
    await newGroup.save();
    console.log('Default community group created');
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
  if (req.user && req.user.role === 'admin') return next();
  res.redirect('/admin/login');
};

// Socket.IO Connection
io.on('connection', (socket) => {
  console.log('a user connected');
  
  // Update user online status
  if (socket.handshake.session.passport && socket.handshake.session.passport.user) {
    const userId = socket.handshake.session.passport.user;
    User.findByIdAndUpdate(userId, { online: true }, { new: true })
      .then(user => {
        io.emit('user status', { userId, online: true });
      });
  }

  // Handle chat messages
  socket.on('chat message', async (msg) => {
    try {
      const userId = socket.handshake.session.passport.user;
      const user = await User.findById(userId);
      
      // Check if user is banned or suspended
      if (user.status !== 'active') return;
      
      // Create message
      const message = new Message({
        content: msg.content,
        sender: userId,
        group: msg.group,
        replyTo: msg.replyTo
      });
      
      const savedMessage = await message.save();
      const populatedMessage = await Message.findById(savedMessage._id).populate('sender');
      
      io.emit('chat message', populatedMessage);
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  // Handle private messages
  socket.on('private message', async (data) => {
    try {
      const senderId = socket.handshake.session.passport.user;
      const sender = await User.findById(senderId);
      
      // Check if sender is allowed to send private messages
      if (sender.status !== 'active' || !sender.privateMessaging) return;
      
      const receiver = await User.findById(data.receiver);
      if (!receiver || !receiver.privateMessaging) return;
      
      // Create private message
      const message = new Message({
        content: data.content,
        sender: senderId,
        receiver: data.receiver,
        replyTo: data.replyTo
      });
      
      const savedMessage = await message.save();
      const populatedMessage = await Message.findById(savedMessage._id).populate('sender');
      
      io.to(data.receiver).emit('private message', populatedMessage);
      socket.emit('private message', populatedMessage);
    } catch (err) {
      console.error('Error saving private message:', err);
    }
  });

  // Handle message deletion
  socket.on('delete message', async (msgId) => {
    try {
      const userId = socket.handshake.session.passport.user;
      const user = await User.findById(userId);
      const message = await Message.findById(msgId).populate('sender');
      
      if (!message) return;
      
      // Check permissions
      if (user.role === 'admin' || message.sender._id.equals(userId)) {
        message.deleted = true;
        message.deletedBy = user.role === 'admin' ? 'admin' : 'user';
        await message.save();
        
        io.emit('message deleted', { 
          id: msgId, 
          deletedBy: message.deletedBy 
        });
      }
    } catch (err) {
      console.error('Error deleting message:', err);
    }
  });

  // Handle message editing
  socket.on('edit message', async (data) => {
    try {
      const userId = socket.handshake.session.passport.user;
      const user = await User.findById(userId);
      const message = await Message.findById(data.id).populate('sender');
      
      if (!message) return;
      
      // Check permissions
      if (user.role === 'admin' || message.sender._id.equals(userId)) {
        message.content = data.content;
        message.updatedAt = new Date();
        await message.save();
        
        io.emit('message edited', message);
      }
    } catch (err) {
      console.error('Error editing message:', err);
    }
  });

  // Handle pin/unpin messages
  socket.on('toggle pin', async (msgId) => {
    try {
      const userId = socket.handshake.session.passport.user;
      const user = await User.findById(userId);
      
      if (user.role !== 'admin') return;
      
      const message = await Message.findById(msgId);
      if (!message) return;
      
      message.pinned = !message.pinned;
      await message.save();
      
      io.emit('message pinned', message);
    } catch (err) {
      console.error('Error toggling pin:', err);
    }
  });

  // Handle disconnection
  socket.on('disconnect', async () => {
    console.log('user disconnected');
    if (socket.handshake.session.passport && socket.handshake.session.passport.user) {
      const userId = socket.handshake.session.passport.user;
      await User.findByIdAndUpdate(userId, { online: false });
      io.emit('user status', { userId, online: false });
    }
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

// Community Chat
app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    // Add user to default group
    const group = await Group.findOne({ name: 'Community' });
    if (!group.members.includes(req.user._id)) {
      group.members.push(req.user._id);
      await group.save();
    }
    
    // Get last 50 messages
    const messages = await Message.find({ group: 'main', deleted: false })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('sender')
      .populate('replyTo');
    
    // Get online users
    const onlineUsers = await User.find({ online: true, status: 'active' });
    
    res.render('chat', { 
      user: req.user, 
      messages: messages.reverse(),
      onlineUsers,
      group
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

// Consolidated Session Route
app.get('/session/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).send('Session not found.');
    }
    if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
      sessionData.status = 'expired';
      await sessionData.save();
    }
    const msLeft = sessionData.expiresAt - Date.now();
    const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;

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

// Admin Update User Role
app.post('/admin/update-role/:userId', isAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    await User.findByIdAndUpdate(req.params.userId, { role });
    res.redirect('/admin');
  } catch (err) {
    console.error('Update role error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Toggle Private Messaging
app.post('/admin/toggle-pm/:userId', isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    user.privateMessaging = !user.privateMessaging;
    await user.save();
    res.redirect('/admin');
  } catch (err) {
    console.error('Toggle PM error:', err);
    res.status(500).send('Internal server error');
  }
});

// User Signup
app.post('/signup', async (req, res) => {
  try {
    const { username, password, confirmPassword } = req.body;
    
    if (password !== confirmPassword) {
      return res.render('signup', { error: 'Passwords do not match' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.render('signup', { error: 'Username already exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
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
    // Create admin session
    req.login({ username, role: 'admin' }, (err) => {
      if (err) return res.status(500).send('Login error');
      res.redirect('/admin');
    });
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

    const download = new Download({
      sessionId,
      status: 'failed',
      error: err.message
    });
    await download.save();

    res.status(500).send('Internal server error.');
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

// Start Server
mongoose.connection.once('open', () => {
  createDefaultGroup();
  const PORT = process.env.PORT || 3000;
  http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
