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
const multer = require('multer');
const axios = require('axios');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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
app.use(express.static(path.join(__dirname, 'public')));
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
  profilePic: { type: String, default: '' },
  phone: { type: String, default: '' },
  bio: { type: String, default: '' },
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

// Chat Models
const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, default: "Main Community" },
  description: { type: String, default: "Official community group" },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String },
  image: { type: String },
  isDeleted: { type: Boolean, default: false },
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  edited: { type: Boolean, default: false },
  pinned: { type: Boolean, default: false },
  replies: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: { type: String },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const privateMessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String },
  image: { type: String },
  isDeleted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Group = mongoose.model('Group', groupSchema);
const Message = mongoose.model('Message', messageSchema);
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

// Authentication Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  if (req.accepts('json')) return res.status(401).json({ error: 'Authentication required' });
  res.redirect('/login');
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.session.isAdmin || (req.user && req.user.isAdmin)) return next();
  res.redirect('/admin/login');
};

// Create default group if not exists
async function createDefaultGroup() {
  const groupExists = await Group.findOne({ name: "Main Community" });
  if (!groupExists) {
    const group = new Group({ name: "Main Community", description: "Official community group" });
    await group.save();
    console.log("Default group created");
  }
}

// Socket.IO Implementation
const onlineUsers = new Map();
const typingUsers = {};

io.on('connection', (socket) => {
  console.log('a user connected');
  
  // User joins the chat
  socket.on('join', async ({ userId }) => {
    try {
      const user = await User.findById(userId);
      if (user) {
        onlineUsers.set(userId, socket.id);
        socket.userId = userId;
        
        // Update user's last seen
        user.lastSeen = new Date();
        await user.save();
        
        // Join main group
        const group = await Group.findOne({ name: "Main Community" });
        if (group) {
          socket.join(group._id.toString());
          
          // Add user to group members if not already
          if (!group.members.includes(userId)) {
            group.members.push(userId);
            await group.save();
          }
        }
        
        // Broadcast user online status
        io.emit('user-status', { userId, status: 'online' });
      }
    } catch (err) {
      console.error('Socket join error:', err);
    }
  });

  // Handle group messages
  socket.on('group-message', async (data) => {
    try {
      const { userId, groupId, content, image } = data;
      const user = await User.findById(userId);
      
      if (user && user.status === 'active') {
        const message = new Message({
          groupId,
          sender: userId,
          content,
          image
        });
        
        const savedMessage = await message.save();
        const populatedMessage = await Message.findById(savedMessage._id).populate('sender');
        
        io.to(groupId).emit('new-group-message', populatedMessage);
      }
    } catch (err) {
      console.error('Group message error:', err);
    }
  });

  // Handle AI commands
  socket.on('ai-command', async (data) => {
    try {
      const { userId, groupId, command, query } = data;
      const user = await User.findById(userId);
      
      if (user && user.status === 'active') {
        // AI APIs
        const aiApis = {
          'gpt': 'https://apis.davidcyriltech.my.id/ai/chatbot?query=',
          'llama3': 'https://apis.davidcyriltech.my.id/ai/llama3?text=',
          'deepseek-v3': 'https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=',
          'deepseek-r1': 'https://apis.davidcyriltech.my.id/ai/deepseek-r1?text=',
          'metaai': 'https://apis.davidcyriltech.my.id/ai/metaai?text=',
          'gpt4': 'https://apis.davidcyriltech.my.id/ai/gpt4?text=',
          'claudeSonnet': 'https://apis.davidcyriltech.my.id/ai/claudeSonnet?text=',
          'uncensor': 'https://apis.davidcyriltech.my.id/ai/uncensor?text=',
          'pixtral': 'https://apis.davidcyriltech.my.id/ai/pixtral?text=',
          'gemma': 'https://apis.davidcyriltech.my.id/ai/gemma?text=',
          'qvq': 'https://apis.davidcyriltech.my.id/ai/qvq?text=',
          'qwen2Coder': 'https://apis.davidcyriltech.my.id/ai/qwen2Coder?text=',
          'gemini': 'https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=',
          'geminiPro': 'https://api.giftedtech.web.id/api/ai/geminiaipro?apikey=gifted&q=',
          'gpt-turbo': 'https://api.giftedtech.web.id/api/ai/gpt-turbo?apikey=gifted&q=',
          'letmegpt': 'https://api.giftedtech.web.id/api/ai/letmegpt?apikey=gifted&query=',
          'simsimi': 'https://api.giftedtech.web.id/api/ai/simsimi?apikey=gifted&query=',
          'luminai': 'https://api.giftedtech.web.id/api/ai/luminai?apikey=gifted&query=',
          'wwdgpt': 'https://api.giftedtech.web.id/api/ai/wwdgpt?apikey=gifted&prompt=',
          'text2img': 'https://api.giftedtech.web.id/api/ai/text2img?apikey=gifted&prompt=',
          'sd': 'https://api.giftedtech.web.id/api/ai/sd?apikey=gifted&prompt=',
          'fluximg': 'https://api.giftedtech.web.id/api/ai/fluximg?apikey=gifted&prompt=',
          'tiktokdlv1': 'https://api.giftedtech.web.id/api/download/tiktokdlv1?apikey=gifted&url='
        };
        
        // Response paths
        const responsePaths = {
          'gpt': 'result',
          'llama3': 'message',
          'deepseek-v3': 'response',
          'deepseek-r1': 'response',
          'metaai': 'response',
          'gpt4': 'message',
          'claudeSonnet': 'response',
          'uncensor': 'response',
          'pixtral': 'response',
          'gemma': 'response',
          'qvq': 'response',
          'qwen2Coder': 'response',
          'gemini': 'result',
          'geminiPro': 'result',
          'gpt-turbo': 'result',
          'letmegpt': 'result',
          'simsimi': 'result',
          'luminai': 'result',
          'wwdgpt': 'result',
          'text2img': 'result',
          'sd': 'result',
          'fluximg': 'result',
          'tiktokdlv1': 'result.video.noWatermark'
        };
        
        let apiUrl = aiApis[command] + encodeURIComponent(query);
        const responsePath = responsePaths[command] || 'result';
        
        // Handle special cases
        if (command === 'tiktokdlv1') {
          apiUrl = aiApis.tiktokdlv1 + encodeURIComponent(query);
        }
        
        try {
          const response = await axios.get(apiUrl);
          const data = response.data;
          
          // Extract response based on path
          let responseText = responsePath.split('.').reduce((o, p) => o?.[p], data);
          
          if (!responseText) {
            responseText = 'This feature is coming soon!';
          }
          
          // Create AI message
          const aiMessage = {
            _id: Date.now().toString(),
            sender: { _id: 'ai', username: 'AI Assistant' },
            content: responseText,
            command: command,
            createdAt: new Date()
          };
          
          // Emit AI response
          io.to(groupId).emit('ai-response', aiMessage);
        } catch (error) {
          console.error('AI API error:', error);
          const aiMessage = {
            _id: Date.now().toString(),
            sender: { _id: 'ai', username: 'AI Assistant' },
            content: 'This feature is coming soon!',
            command: command,
            createdAt: new Date()
          };
          io.to(groupId).emit('ai-response', aiMessage);
        }
      }
    } catch (err) {
      console.error('AI command error:', err);
    }
  });

  // Typing indicator
  socket.on('typing', ({ groupId, userId, isTyping }) => {
    if (isTyping) {
      typingUsers[userId] = setTimeout(() => {
        delete typingUsers[userId];
        io.to(groupId).emit('typing', { userId, isTyping: false });
      }, 3000);
    } else {
      if (typingUsers[userId]) {
        clearTimeout(typingUsers[userId]);
        delete typingUsers[userId];
      }
    }
    io.to(groupId).emit('typing', { userId, isTyping });
  });

  // User disconnects
  socket.on('disconnect', async () => {
    console.log('user disconnected');
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      
      // Update user's last seen
      const user = await User.findById(socket.userId);
      if (user) {
        user.lastSeen = new Date();
        await user.save();
      }
      
      // Broadcast user offline status
      io.emit('user-status', { userId: socket.userId, status: 'offline' });
    }
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));
app.get('/api', (req, res) => res.render('api'));

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

// Chat Community
app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    const group = await Group.findOne({ name: "Main Community" }).populate('members');
    const messages = await Message.find({ groupId: group._id, isDeleted: false })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('sender')
      .populate('replies.sender');
    
    res.render('chat', { 
      user: req.user,
      group,
      messages: messages.reverse(),
      onlineUsers: Array.from(onlineUsers.keys()),
      whatsappLink: process.env.WHATSAPP_LINK || 'https://whatsapp.com/channel/0029Va9A8b4Jz9l4Z5z5Z5Z5'
    });
  } catch (err) {
    console.error('Chat error:', err);
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

// Admin Promote to Admin
app.post('/admin/promote-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { isAdmin: true });
    res.redirect('/admin');
  } catch (err) {
    console.error('Promote user error:', err);
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
    
    // Add user to default group
    const group = await Group.findOne({ name: "Main Community" });
    if (group && !group.members.includes(user._id)) {
      group.members.push(user._id);
      await group.save();
    }
    
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

// Update user profile
app.post('/update-profile', isAuthenticated, upload.single('profilePic'), async (req, res) => {
  try {
    const { phone, bio } = req.body;
    const user = req.user;
    
    user.phone = phone || '';
    user.bio = bio || '';
    
    if (req.file) {
      // In a real app, you'd upload to cloud storage and save URL
      // For demo, we'll just save a placeholder
      user.profilePic = `https://ui-avatars.com/api/?name=${user.username}&background=random`;
    }
    
    await user.save();
    res.redirect('/chat');
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).send('Internal server error');
  }
});

// Get user profile
app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    const isOnline = onlineUsers.has(user._id.toString());
    res.render('profile', { profileUser: user, currentUser: req.user, isOnline });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal server error');
  }
});

// Start Server
mongoose.connection.once('open', async () => {
  await createDefaultGroup();
  
  const PORT = process.env.PORT || 3000;
  http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
