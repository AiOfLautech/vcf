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
});

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isSuspended: { type: Boolean, default: false },
  suspendedUntil: { type: Date },
  createdAt: { type: Date, default: Date.now },
  profile: {
    name: String,
    phone: String,
    bio: String,
    profilePic: String,
    status: String
  }
});

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  groupName: { type: String, required: true },
  whatsappLink: String,
  timer: { type: Number, default: 60 },
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
  error: String
});

const messageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: { type: String, required: true },
  isDeleted: { type: Boolean, default: false },
  editedAt: Date,
  createdAt: { type: Date, default: Date.now },
  messageType: { type: String, enum: ['text', 'reply', 'ai'], default: 'text' },
  repliedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session setup
const MongoStore = require('connect-mongo');
const store = MongoStore.create({ 
  mongoUrl: process.env.MONGO_URL,
  collectionName: 'sessions'
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Passport setup
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      
      if (user.isSuspended && (!user.suspendedUntil || new Date() < user.suspendedUntil)) {
        return done(null, false, { message: 'Your account is suspended.' });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) return done(null, false, { message: 'Incorrect password.' });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// Helper middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') return next();
  res.redirect('/');
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/login', (req, res) => {
  res.render('login', { error: req.flash('error') });
});

app.post('/login', 
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/signup', (req, res) => {
  res.render('signup', { error: req.flash('error') });
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({ 
      username, 
      password: hashedPassword,
      email,
      role: 'user'
    });
    
    await user.save();
    res.redirect('/login');
  } catch (err) {
    req.flash('error', 'Username already exists');
    res.redirect('/signup');
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.render('dashboard', { user: req.user, sessions });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/create-session', isAuthenticated, (req, res) => {
  res.render('create-session', { user: req.user });
});

app.post('/create-session', isAuthenticated, async (req, res) => {
  try {
    const { groupName, whatsappLink, timer } = req.body;
    const sessionId = crypto.randomBytes(3).toString('hex').toUpperCase();
    const minutes = parseInt(timer) || 60;
    const expiresAt = new Date(Date.now() + minutes * 60 * 1000);
    
    const session = new Session({
      sessionId,
      userId: req.user._id,
      groupName,
      whatsappLink,
      timer: minutes,
      expiresAt
    });
    
    await session.save();
    res.redirect(`/session/${sessionId}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating session');
  }
});

app.get('/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const sessionData = await Session.findOne({ sessionId });
    
    if (!sessionData) return res.render('notfound');
    if (sessionData.status === 'deleted') return res.render('error', { title: 'Session Deleted', message: 'This session has been deleted by the admin.' });
    
    const totalSeconds = Math.max(0, Math.floor((sessionData.expiresAt - Date.now()) / 1000));
    const whatsappLink = sessionData.whatsappLink || '';
    
    res.render('session', { 
      sessionId, 
      groupName: sessionData.groupName,
      totalSeconds,
      whatsappLink
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/session/:sessionId/contact', async (req, res) => {
  const { sessionId } = req.params;
  const { name, phone } = req.body;
  
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone are required.' });
  
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
      vcfData += `BEGIN:VCARD\nVERSION:3.0\nFN:${contact.name}\nTEL;TYPE=CELL:${contact.phone}\nEND:VCARD\n`;
    });
    
    const fileName = `${sessionData.groupName.replace(/[^a-z0-9]/gi, '_')}_${sessionId}.vcf`;
    const download = new Download({ sessionId, status: 'success' });
    await download.save();
    
    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(vcfData || 'No contacts were added.');
  } catch (err) {
    console.error('Download error:', err);
    const download = new Download({ sessionId, status: 'failed', error: err.message });
    await download.save();
    res.status(500).send('Internal server error');
  }
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const profileUser = await User.findById(req.params.userId);
    if (!profileUser) return res.status(404).send('User not found');
    
    // Calculate server uptime
    const uptime = process.uptime();
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    
    // Get current time
    const now = new Date();
    const timeNow = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    const dateToday = now.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
    
    // Get memory usage (simplified for example)
    const totalMemory = (process.memoryUsage().heapTotal / (1024 * 1024 * 1024)).toFixed(2);
    const usedMemory = (process.memoryUsage().heapUsed / (1024 * 1024 * 1024)).toFixed(2);
    
    res.render('profile', { 
      user: req.user,
      profileUser,
      uptime: `${days}d ${hours}h ${minutes}m ${seconds}s`,
      timeNow,
      dateToday,
      totalMemory,
      usedMemory
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/edit-profile', isAuthenticated, (req, res) => {
  res.render('edit-profile', { user: req.user });
});

app.post('/edit-profile', isAuthenticated, async (req, res) => {
  try {
    const { name, phone, bio, profilePic } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      profile: { name, phone, bio, profilePic }
    });
    res.redirect('/profile/' + req.user._id);
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/chat', isAuthenticated, (req, res) => {
  res.render('chat', { user: req.user });
});

app.get('/conversations', isAuthenticated, async (req, res) => {
  try {
    // Get all conversations for the user (distinct recipients)
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { userId: req.user._id },
            { recipient: req.user._id }
          ]
        }
      },
      {
        $sort: { createdAt: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $lt: ["$userId", "$recipient"] },
              { from: "$userId", to: "$recipient" },
              { from: "$recipient", to: "$userId" }
            ]
          },
          lastMessage: { $first: "$$ROOT" }
        }
      },
      {
        $lookup: {
          from: "users",
          localField: "_id.to",
          foreignField: "_id",
          as: "recipient"
        }
      },
      {
        $unwind: "$recipient"
      },
      {
        $project: {
          "recipient.password": 0,
          "recipient._id": 0
        }
      },
      {
        $sort: { "lastMessage.createdAt": -1 }
      }
    ]);

    res.render('conversations', { user: req.user, conversations });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  try {
    const recipient = await User.findById(req.params.userId);
    if (!recipient) return res.status(404).send('User not found');
    
    const messages = await Message.find({
      $or: [
        { userId: req.user._id, recipient: recipient._id },
        { userId: recipient._id, recipient: req.user._id }
      ]
    }).sort({ createdAt: 1 });
    
    res.render('private-chat', { 
      user: req.user, 
      recipient,
      messages 
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/api/messages', isAuthenticated, async (req, res) => {
  try {
    const { content, recipientId, messageType, repliedTo } = req.body;
    
    const message = new Message({
      userId: req.user._id,
      recipient: recipientId,
      content,
      messageType,
      repliedTo: messageType === 'reply' ? repliedTo : null
    });
    
    await message.save();
    
    // Populate user data for socket emission
    const populatedMessage = await Message.findById(message._id)
      .populate('userId', 'username profile.name profile.profilePic');
    
    // Emit to recipient if online
    if (io.sockets.adapter.rooms.get(`user_${recipientId}`)) {
      io.to(`user_${recipientId}`).emit('new-message', populatedMessage);
    }
    
    res.json({ success: true, message: populatedMessage });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.post('/api/messages/:messageId/edit', isAuthenticated, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { content } = req.body;
    
    const message = await Message.findOne({ 
      _id: messageId, 
      userId: req.user._id 
    });
    
    if (!message) return res.status(404).json({ error: 'Message not found or unauthorized' });
    
    message.content = content;
    message.editedAt = new Date();
    await message.save();
    
    // Populate user data for socket emission
    const populatedMessage = await Message.findById(message._id)
      .populate('userId', 'username profile.name profile.profilePic');
    
    // Broadcast update to all participants
    const recipientId = message.recipient.toString();
    if (io.sockets.adapter.rooms.get(`user_${recipientId}`)) {
      io.to(`user_${recipientId}`).emit('message-updated', populatedMessage);
    }
    io.to(`user_${req.user._id}`).emit('message-updated', populatedMessage);
    
    res.json({ success: true, message: populatedMessage });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to edit message' });
  }
});

app.post('/api/messages/:messageId/delete', isAuthenticated, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findOne({ 
      _id: messageId, 
      userId: req.user._id 
    });
    
    if (!message) return res.status(404).json({ error: 'Message not found or unauthorized' });
    
    message.isDeleted = true;
    await message.save();
    
    // Populate user data for socket emission
    const populatedMessage = await Message.findById(message._id)
      .populate('userId', 'username profile.name profile.profilePic');
    
    // Broadcast update to all participants
    const recipientId = message.recipient.toString();
    if (io.sockets.adapter.rooms.get(`user_${recipientId}`)) {
      io.to(`user_${recipientId}`).emit('message-deleted', populatedMessage);
    }
    io.to(`user_${req.user._id}`).emit('message-deleted', populatedMessage);
    
    res.json({ success: true, message: populatedMessage });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Admin routes
app.get('/admin/login', (req, res) => {
  res.render('admin-login', { error: req.flash('error') });
});

app.post('/admin/login', 
  passport.authenticate('local', {
    successRedirect: '/admin',
    failureRedirect: '/admin/login',
    failureFlash: true
  })
);

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const totalSessions = await Session.countDocuments();
    const activeSessions = await Session.countDocuments({ status: 'active' });
    const expiredOrDeletedSessions = await Session.countDocuments({ 
      $or: [{ status: 'expired' }, { status: 'deleted' }] 
    });
    const totalContacts = await Contact.countDocuments();
    const sessionsWithWhatsapp = await Session.countDocuments({ whatsappLink: { $ne: null } });
    const sessions = await Session.find().sort({ createdAt: -1 });
    const recentSessions = await Session.find().sort({ createdAt: -1 }).limit(5).populate('userId');
    const recentDownloads = await Download.find().sort({ timestamp: -1 }).limit(5);
    const users = await User.find();
    
    res.render('admin', {
      stats: {
        totalSessions,
        activeSessions,
        expiredOrDeletedSessions,
        totalContacts,
        sessionsWithWhatsapp
      },
      sessions,
      recentSessions,
      recentDownloads,
      users,
      user: req.user
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/admin/user/:userId/suspend', isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { duration } = req.body;
    
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const suspendedUntil = new Date(Date.now() + parseInt(duration) * 60 * 1000);
    user.isSuspended = true;
    user.suspendedUntil = suspendedUntil;
    await user.save();
    
    // Notify user via socket if online
    if (io.sockets.adapter.rooms.get(`user_${userId}`)) {
      io.to(`user_${userId}`).emit('account-suspended', {
        suspendedUntil: suspendedUntil.toISOString(),
        message: `Your account has been suspended for ${duration} minutes.`
      });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to suspend user' });
  }
});

app.post('/admin/user/:userId/unsuspend', isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    user.isSuspended = false;
    user.suspendedUntil = null;
    await user.save();
    
    // Notify user via socket if online
    if (io.sockets.adapter.rooms.get(`user_${userId}`)) {
      io.to(`user_${userId}`).emit('account-unsuspended', {
        message: 'Your account has been unsuspended.'
      });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to unsuspend user' });
  }
});

app.post('/admin/session/:sessionId/delete', isAdmin, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const session = await Session.findOne({ sessionId });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    session.status = 'deleted';
    await session.save();
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete session' });
  }
});

// AI API endpoint
app.post('/api/ai', isAuthenticated, async (req, res) => {
  try {
    const { query, model } = req.body;
    
    // Simulate AI response (in a real app, this would call an actual AI API)
    const aiResponse = {
      creator: "Contact Gain",
      response: `This is a response from the ${model} model to your query: "${query}". Contact Gain helps you build your network and grow your business.`,
      timestamp: new Date().toISOString()
    };
    
    res.json(aiResponse);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// Socket.io setup
io.use((socket, next) => {
  const userId = socket.handshake.auth.userId;
  if (!userId) {
    return next(new Error('Authentication error'));
  }
  socket.userId = userId;
  next();
});

io.on('connection', (socket) => {
  console.log('New client connected:', socket.userId);
  
  // Join user room
  socket.join(`user_${socket.userId}`);
  
  // Typing indicator
  socket.on('typing', (data) => {
    if (data.recipientId) {
      socket.to(`user_${data.recipientId}`).emit('user-typing', {
        userId: socket.userId,
        isTyping: data.isTyping
      });
    }
  });
  
  // AI request
  socket.on('ai-request', async (data) => {
    try {
      const response = await axios.post('/api/ai', {
        query: data.query,
        model: data.model
      }, {
        headers: { 'Cookie': socket.handshake.headers.cookie }
      });
      
      socket.emit('ai-response', {
        ...response.data,
        userId: data.userId
      });
    } catch (err) {
      socket.emit('ai-response', {
        error: 'Failed to get AI response',
        userId: data.userId
      });
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.userId);
  });
});

// Default group creation
async function createDefaultGroup() {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await User.create({
        username: process.env.ADMIN_USERNAME,
        password: hashedPassword,
        role: 'admin'
      });
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
}

// Start Server
mongoose.connection.once('open', () => {
  createDefaultGroup();
  const PORT = process.env.PORT || 3000;
  http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
