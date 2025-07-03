require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { createServer } = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const sharp = require('sharp');
const OpenAI = require('openai');
const MongoStore = require('connect-mongo');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Configure OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration with separate collection
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  },
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URL,
    collectionName: 'express_sessions', // Prevent conflict
    ttl: 24 * 60 * 60 
  })
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

// Configure Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'), false);
    }
  }
});

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  avatar: { type: String },
  phone: { type: String },
  bio: { type: String },
  isAdmin: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

// Sparse index to handle null values
const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sessionId: { 
    type: String, 
    unique: true, 
    required: true,
    index: { unique: true, sparse: true } 
  },
  groupName: { type: String, required: true },
  whatsappLink: { type: String },
  timer: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  downloadCount: { type: Number, default: 0 },
  contactCount: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'expired', 'deleted'], default: 'active' },
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' }
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
  sessionId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: { type: String },
  image: { type: String },
  timestamp: { type: Date, default: Date.now },
  edited: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  deletedBy: { type: String, enum: ['user', 'admin'] },
  replies: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  pinned: { type: Boolean, default: false }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: 'Community group for sharing contacts' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const privateMessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);
const PrivateMessage = mongoose.model('PrivateMessage', privateMessageSchema);

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

// Authentication Middleware - FIXED
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated() || req.session.adminAuthenticated) {
    return next();
  }
  if (req.accepts('json')) return res.status(401).json({ error: 'Authentication required' });
  res.redirect('/login');
};

// Admin middleware - FIXED
const isAdmin = (req, res, next) => {
  if ((req.user && req.user.isAdmin) || req.session.adminAuthenticated) {
    return next();
  }
  res.redirect('/admin/login');
};

// Socket.IO Logic
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // Update user last seen time
  socket.on('user-online', async (userId) => {
    try {
      await User.findByIdAndUpdate(userId, { lastSeen: new Date() });
      socket.broadcast.emit('user-status-changed', { userId, online: true });
    } catch (err) {
      console.error('Update online status error:', err);
    }
  });

  // Join session room
  socket.on('join-session', async (sessionId) => {
    socket.join(sessionId);
    try {
      const sessionData = await Session.findOne({ sessionId });
      if (!sessionData) return;
      
      // Add user to group if not already added
      const group = await Group.findById(sessionData.groupId);
      if (group && socket.request.session.passport) {
        const userId = socket.request.session.passport.user;
        if (!group.members.includes(userId)) {
          group.members.push(userId);
          await group.save();
        }
      }
      
      // Emit online users
      const sockets = await io.in(sessionId).fetchSockets();
      const userIds = sockets.map(s => s.request.session.passport?.user).filter(id => id);
      io.to(sessionId).emit('online-users', userIds);
    } catch (err) {
      console.error('Join session error:', err);
    }
  });

  // Handle chat messages
  socket.on('chat-message', async (data) => {
    try {
      // AI command handling
      if (data.content && data.content.startsWith('/GTP')) {
        const prompt = data.content.replace('/GTP', '').trim();
        const completion = await openai.chat.completions.create({
          messages: [{ role: "user", content: prompt }],
          model: "gpt-3.5-turbo",
        });
        
        const aiResponse = completion.choices[0].message.content;
        io.to(data.sessionId).emit('ai-response', {
          sessionId: data.sessionId,
          content: aiResponse,
          isAI: true
        });
        return;
      }
      
      // Save message to DB
      const message = new Message({
        sessionId: data.sessionId,
        userId: data.userId,
        content: data.content,
        image: data.image
      });
      
      await message.save();
      
      // Broadcast message to room
      io.to(data.sessionId).emit('new-message', message);
    } catch (err) {
      console.error('Chat message error:', err);
    }
  });

  // Handle typing indicators
  socket.on('typing', (data) => {
    socket.to(data.sessionId).emit('user-typing', {
      userId: data.userId,
      username: data.username
    });
  });

  // Handle message deletion
  socket.on('delete-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (!message) return;
      
      if (message.userId.toString() === data.userId || data.isAdmin) {
        message.deleted = true;
        message.deletedBy = data.isAdmin ? 'admin' : 'user';
        await message.save();
        
        io.to(data.sessionId).emit('message-deleted', {
          messageId: data.messageId,
          deletedBy: message.deletedBy
        });
      }
    } catch (err) {
      console.error('Delete message error:', err);
    }
  });

  // Handle message editing
  socket.on('edit-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (!message || message.deleted) return;
      
      if (message.userId.toString() === data.userId || data.isAdmin) {
        message.content = data.newContent;
        message.edited = true;
        await message.save();
        
        io.to(data.sessionId).emit('message-edited', {
          messageId: data.messageId,
          newContent: data.newContent
        });
      }
    } catch (err) {
      console.error('Edit message error:', err);
    }
  });

  // Handle private messages
  socket.on('private-message', async (data) => {
    try {
      const privateMessage = new PrivateMessage({
        sender: data.senderId,
        receiver: data.receiverId,
        content: data.content
      });
      
      await privateMessage.save();
      
      // Emit to sender and receiver
      io.to(socket.id).emit('new-private-message', privateMessage);
      socket.to(`user-${data.receiverId}`).emit('new-private-message', privateMessage);
    } catch (err) {
      console.error('Private message error:', err);
    }
  });

  // Disconnect handler
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));
app.get('/admin/login', (req, res) => res.render('admin-login'));

// Redirect routes - FIXED
app.get('/profile', isAuthenticated, (req, res) => {
  res.redirect(`/profile/${req.user ? req.user._id : req.session.adminUserId}`);
});

app.get('/chat', isAuthenticated, (req, res) => {
  res.redirect('/terminal');
});

// Terminal (Dashboard)
app.get('/terminal', isAuthenticated, async (req, res) => {
  try {
    // Handle admin user differently
    const userId = req.user ? req.user._id : req.session.adminUserId;
    if (!userId) {
      return res.redirect('/login');
    }

    const sessions = await Session.find({ userId }).sort({ createdAt: -1 });
    const totalContacts = await Contact.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
    const totalSessions = sessions.length;
    const activeSessions = sessions.filter(s => s.status === 'active').length;
    const totalDownloads = await Download.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
    const avgContacts = totalSessions > 0 ? (totalContacts / totalSessions).toFixed(1) : 0;

    res.render('terminal', { 
      user: req.user || { isAdmin: true }, 
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

// Admin Dashboard - FIXED
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

// Chat Interface
app.get('/chat/:sessionId', isAuthenticated, async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    const sessionData = await Session.findOne({ sessionId }).populate('groupId');
    if (!sessionData) return res.status(404).send('Session not found');
    
    // Get or create group
    let group = sessionData.groupId;
    if (!group) {
      group = new Group({
        name: sessionData.groupName,
        members: [req.user._id],
        admins: [req.user._id]
      });
      await group.save();
      
      sessionData.groupId = group._id;
      await sessionData.save();
    }
    
    // Add user to group if not already
    if (!group.members.includes(req.user._id)) {
      group.members.push(req.user._id);
      await group.save();
    }
    
    // Get messages
    const messages = await Message.find({ sessionId })
      .sort({ timestamp: -1 })
      .limit(50)
      .populate('userId');
    
    // Get members with online status
    const allSockets = await io.fetchSockets();
    const onlineUserIds = allSockets
      .map(s => s.request.session.passport?.user)
      .filter(id => id);
    
    const members = await User.find({ _id: { $in: group.members } });
    const membersWithStatus = members.map(member => ({
      ...member.toObject(),
      online: onlineUserIds.includes(member._id.toString())
    }));
    
    res.render('chat', {
      sessionId,
      groupName: sessionData.groupName,
      groupDescription: group.description,
      messages: messages.reverse(),
      members: membersWithStatus,
      user: req.user || { isAdmin: true }
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).send('Internal server error');
  }
});

// User Profile
app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).send('User not found');
    
    // Check online status
    const allSockets = await io.fetchSockets();
    const onlineUserIds = allSockets
      .map(s => s.request.session.passport?.user)
      .filter(id => id);
    
    const isOnline = onlineUserIds.includes(user._id.toString());
    
    res.render('profile', {
      user,
      isOnline,
      currentUser: req.user || { isAdmin: true }
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal server error');
  }
});

// Upload profile picture
app.post('/upload-profile-pic', isAuthenticated, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');
    
    // Process image
    const buffer = await sharp(req.file.buffer)
      .resize(300, 300)
      .png()
      .toBuffer();
    
    const filename = `${req.user._id}-${Date.now()}.png`;
    const filepath = path.join(__dirname, 'public', 'uploads', filename);
    
    require('fs').writeFileSync(filepath, buffer);
    
    // Update user
    await User.findByIdAndUpdate(req.user._id, { avatar: `/uploads/${filename}` });
    
    res.redirect(`/profile/${req.user._id}`);
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).send('Internal server error');
  }
});

// Consolidated Session Route
app.get('/session/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) return res.status(404).send('Session not found.');
    
    // Check if session is expired
    if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
      sessionData.status = 'expired';
      await sessionData.save();
    }
    
    // Calculate remaining time
    const msLeft = sessionData.expiresAt - Date.now();
    const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;

    // Get recommended sessions
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
    const userId = req.user ? req.user._id : req.session.adminUserId;
    const session = await Session.findOne({ sessionId: req.params.sessionId, userId });
    if (!session) return res.status(404).send('Session not found');
    await session.remove();
    res.redirect('/terminal');
  } catch (err) {
    console.error('Delete session error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin User Management
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
    if (req.body.password !== req.body.confirmPassword) {
      return res.render('signup', { error: 'Passwords do not match' });
    }
    
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) return res.render('signup', { error: 'Username already exists' });
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ 
      username: req.body.username, 
      password: hashedPassword 
    });
    
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
    req.session.destroy();
    res.redirect('/');
  });
});

// Admin Login - FIXED
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username, isAdmin: true });
    if (user && await bcrypt.compare(password, user.password)) {
      // Create admin session
      req.session.adminAuthenticated = true;
      req.session.adminUserId = user._id;
      return res.redirect('/admin');
    }
    
    // Check system admin credentials
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      req.session.adminAuthenticated = true;
      return res.redirect('/admin');
    }
    
    res.render('admin-login', { error: 'Invalid credentials' });
  } catch (err) {
    console.error('Admin login error:', err);
    res.render('admin-login', { error: 'Internal server error' });
  }
});

// Create Session
app.post('/create-session', isAuthenticated, async (req, res) => {
  const { groupName, timer, whatsappLink } = req.body;
  if (!groupName || !timer) return res.status(400).json({ error: 'Group name and timer are required.' });
  if (isNaN(timer) || timer <= 0 || timer > 1440) return res.status(400).json({ error: 'Timer must be a positive number up to 1440 minutes.' });
  
  // Generate unique session ID
  let sessionId;
  let sessionExists;
  let attempts = 0;
  
  do {
    sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
    sessionExists = await Session.findOne({ sessionId });
    attempts++;
  } while (sessionExists && attempts < 5);
  
  if (sessionExists) {
    return res.status(500).json({ error: 'Failed to generate unique session ID' });
  }

  const now = Date.now();
  const expiresAt = new Date(now + parseInt(timer) * 60 * 1000);
  
  try {
    const userId = req.user ? req.user._id : req.session.adminUserId;
    
    const session = new Session({
      userId,
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
    if (!sessionData) return res.status(404).json({ error: 'Session not found.' });

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
    if (!sessionData) return res.status(404).send('Session not found.');

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
  const PORT = process.env.PORT || 3000;
  httpServer.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
