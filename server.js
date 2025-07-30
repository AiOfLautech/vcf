require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const socketIo = require('socket.io');
const axios = require('axios');
const moment = require('moment');
const path = require('path');
const flash = require('connect-flash');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Database Models
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isSuperAdmin: { type: Boolean, default: false },
  isSuspended: { type: Boolean, default: false },
  suspendedAt: Date,
  lastSeen: Date,
  profile: {
    name: String,
    phone: String,
    bio: String,
    profilePic: String
  }
});

const SessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  groupName: { type: String, required: true },
  whatsappGroup: String,
  timer: { type: Number, default: 60 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  downloadCount: { type: Number, default: 0 }
});

const ContactSchema = new mongoose.Schema({
  sessionId: String,
  name: String,
  phone: String,
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  edited: { type: Boolean, default: false },
  isSystem: { type: Boolean, default: false }
});

const DownloadSchema = new mongoose.Schema({
  sessionId: String,
  status: String,
  error: String,
  createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', UserSchema);
const Session = mongoose.model('Session', SessionSchema);
const Contact = mongoose.model('Contact', ContactSchema);
const Message = mongoose.model('Message', MessageSchema);
const Download = mongoose.model('Download', DownloadSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', async () => {
  console.log('Connected to MongoDB');
  
  // Cleanup sessions with null sessionId
  await Session.deleteMany({ sessionId: null });
  
  // Create default admin if not exists
  User.findOne({ username: process.env.ADMIN_USERNAME }).then(user => {
    if (!user) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, salt);
      
      new User({
        username: process.env.ADMIN_USERNAME,
        password: hash,
        isAdmin: true,
        isSuperAdmin: false
      }).save();
    }
  });
  
  // Create super admin if not exists
  User.findOne({ username: process.env.SUPER_ADMIN_USERNAME }).then(user => {
    if (!user) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(process.env.SUPER_ADMIN_PASSWORD, salt);
      
      new User({
        username: process.env.SUPER_ADMIN_USERNAME,
        password: hash,
        isAdmin: true,
        isSuperAdmin: true
      }).save();
    }
  });
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URL,
    ttl: 24 * 60 * 60 // 24 hours
  }),
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Passport config
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      
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

// Set EJS as template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Global variables
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Helper functions
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error_msg', 'Please log in to view that resource');
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.isAdmin) {
    return next();
  }
  req.flash('error_msg', 'You do not have permission to view that resource');
  res.redirect('/');
}

// Routes
app.get('/', (req, res) => {
  res.render('landing');
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

app.post('/login', 
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Create Account' });
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password, confirmPassword } = req.body;
    
    if (password !== confirmPassword) {
      req.flash('error', 'Passwords do not match');
      return res.redirect('/signup');
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash('error', 'Username already exists');
      return res.redirect('/signup');
    }
    
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    
    const newUser = new User({
      username,
      password: hash,
      profile: {
        name: username,
        bio: 'Hello, I\'m using Contact Gain!'
      }
    });
    
    await newUser.save();
    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    req.flash('error', 'Error registering user');
    res.redirect('/signup');
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    req.flash('success_msg', 'You are logged out');
    res.redirect('/');
  });
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const sessions = await Session.find().sort({ createdAt: -1 }).limit(10);
    const totalUsers = await User.countDocuments();
    const totalSessions = await Session.countDocuments();
    const totalContacts = await Contact.countDocuments();
    
    res.render('dashboard', {
      title: 'Dashboard',
      sessions,
      totalUsers,
      totalSessions,
      totalContacts
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load dashboard'
    });
  }
});

app.get('/profile/:id', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.render('error', {
        title: 'Not Found',
        message: 'User not found'
      });
    }
    
    // Get last seen information
    let lastSeen = 'Online';
    if (user.lastSeen) {
      const now = moment();
      const diff = moment.duration(now.diff(user.lastSeen));
      
      if (diff.asHours() > 24) {
        lastSeen = moment(user.lastSeen).format('MMM D, YYYY');
      } else if (diff.asHours() > 1) {
        lastSeen = `${Math.floor(diff.asHours())} hours ago`;
      } else if (diff.asMinutes() > 1) {
        lastSeen = `${Math.floor(diff.asMinutes())} minutes ago`;
      } else {
        lastSeen = 'Just now';
      }
    }
    
    res.render('profile', {
      title: `${user.profile?.name || user.username}'s Profile`,
      profileUser: user,
      lastSeen
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load profile'
    });
  }
});

app.get('/edit-profile', isAuthenticated, (req, res) => {
  res.render('edit-profile', {
    title: 'Edit Profile'
  });
});

app.post('/edit-profile', isAuthenticated, async (req, res) => {
  try {
    const { name, phone, bio, profilePic } = req.body;
    
    // Update user profile
    await User.findByIdAndUpdate(req.user._id, {
      profile: {
        name,
        phone,
        bio,
        profilePic
      }
    });
    
    req.flash('success_msg', 'Profile updated successfully');
    res.redirect(`/profile/${req.user._id}`);
  } catch (err) {
    console.error('Profile update error:', err);
    req.flash('error', 'Failed to update profile');
    res.redirect('/edit-profile');
  }
});

app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    // Get recent conversations
    const conversations = await Message.aggregate([
      { $match: { 
        $or: [
          { userId: req.user._id },
          { recipient: req.user._id }
        ]
      }},
      { $sort: { createdAt: -1 }},
      { $group: {
        _id: {
          $cond: [
            { $gt: [{ $toString: "$userId" }, { $toString: "$recipient" }] },
            { sender: "$recipient", receiver: "$userId" },
            { sender: "$userId", receiver: "$recipient" }
          ]
        },
        lastMessage: { $first: "$$ROOT" }
      }}
    ]);
    
    // Format conversations for display
    const formattedConversations = await Promise.all(conversations.map(async conv => {
      const otherUserId = conv._id.sender.toString() === req.user._id.toString() ? 
        conv._id.receiver : conv._id.sender;
      
      const otherUser = await User.findById(otherUserId);
      return {
        ...conv,
        otherUser
      };
    }));
    
    res.render('chat', {
      title: 'Community Chat',
      conversations: formattedConversations
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load chat'
    });
  }
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  try {
    const recipient = await User.findById(req.params.userId);
    if (!recipient) {
      return res.render('error', {
        title: 'Not Found',
        message: 'User not found'
      });
    }
    
    // Get messages between users
    const messages = await Message.find({
      $or: [
        { userId: req.user._id, recipient: recipient._id },
        { userId: recipient._id, recipient: req.user._id }
      ]
    }).sort({ createdAt: 1 });
    
    res.render('private-chat', {
      title: `Chat with ${recipient.profile?.name || recipient.username}`,
      recipient,
      messages
    });
  } catch (err) {
    console.error('Private chat error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load private chat'
    });
  }
});

app.get('/create-session', isAuthenticated, (req, res) => {
  res.render('create-session', { title: 'Create Session' });
});

app.post('/create-session', isAuthenticated, async (req, res) => {
  try {
    const { groupName, whatsappGroup, timer } = req.body;
    
    // Generate unique session ID with retry logic
    let sessionId;
    let sessionExists;
    let attempts = 0;
    const maxAttempts = 5;
    
    do {
      sessionId = uuidv4().substring(0, 9).toUpperCase();
      sessionExists = await Session.findOne({ sessionId });
      attempts++;
    } while (sessionExists && attempts < maxAttempts);
    
    if (sessionExists) {
      req.flash('error', 'Failed to generate unique session ID. Please try again.');
      return res.redirect('/create-session');
    }
    
    const session = new Session({
      sessionId,
      groupName,
      whatsappGroup,
      timer: parseInt(timer) || 60,
      createdBy: req.user._id
    });
    
    await session.save();
    
    req.flash('success_msg', 'Session created successfully');
    res.redirect(`/session/${sessionId}`);
  } catch (err) {
    console.error('Session creation error:', err);
    req.flash('error', 'Failed to create session');
    res.redirect('/create-session');
  }
});

app.get('/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const sessionData = await Session.findOne({ sessionId });
    
    if (!sessionData) {
      return res.render('error', {
        title: 'Session Not Found',
        message: 'The session you are looking for does not exist'
      });
    }
    
    // Calculate remaining time
    const now = new Date();
    const expiresAt = new Date(sessionData.createdAt);
    expiresAt.setMinutes(expiresAt.getMinutes() + sessionData.timer);
    const remainingSeconds = Math.max(0, Math.floor((expiresAt - now) / 1000));
    
    res.render('session', {
      title: sessionData.groupName,
      session: sessionData,
      remainingSeconds,
      totalSeconds: sessionData.timer * 60
    });
  } catch (err) {
    console.error('Session error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load session'
    });
  }
});

app.post('/session/:sessionId/contact', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { name, phone } = req.body;
    
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    // Validate contact data
    if (!name || !phone) {
      return res.status(400).json({ success: false, error: 'Name and phone are required' });
    }
    
    // Create contact
    const contact = new Contact({
      sessionId,
      name,
      phone
    });
    
    await contact.save();
    
    res.json({ success: true });
  } catch (err) {
    console.error('Contact error:', err);
    res.status(500).json({ success: false, error: 'Failed to add contact' });
  }
});

app.get('/session/:sessionId/download', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const sessionData = await Session.findOne({ sessionId });
    
    if (!sessionData) {
      return res.status(404).send('Session not found');
    }
    
    sessionData.downloadCount += 1;
    await sessionData.save();
    
    const contacts = await Contact.find({ sessionId });
    let vcfData = '';
    
    contacts.forEach(contact => {
      vcfData += `BEGIN:VCARD\n`;
      vcfData += `VERSION:3.0\n`;
      vcfData += `FN:${contact.name}\n`;
      vcfData += `TEL;TYPE=CELL:${contact.phone}\n`;
      vcfData += `END:VCARD\n\n`;
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
    res.status(500).send('Internal server error');
  }
});

app.get('/api', (req, res) => {
  res.render('api', { title: 'API Documentation' });
});

// AI API endpoints
app.post('/api/ai', isAuthenticated, async (req, res) => {
  try {
    const { model, query } = req.body;
    
    if (!model || !query) {
      return res.status(400).json({
        creator: "Contact Gain",
        status: 400,
        success: false,
        error: "Model and query are required"
      });
    }
    
    // Call the appropriate AI API
    let apiUrl = '';
    let responseKey = '';
    
    switch (model) {
      case 'gpt':
        apiUrl = `https://apis.davidcyriltech.my.id/ai/chatbot?query=${encodeURIComponent(query)}`;
        responseKey = 'result';
        break;
      case 'llama':
        apiUrl = `https://apis.davidcyriltech.my.id/ai/llama3?text=${encodeURIComponent(query)}`;
        responseKey = 'message';
        break;
      case 'deepseek':
        apiUrl = `https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=${encodeURIComponent(query)}`;
        responseKey = 'response';
        break;
      case 'gemini':
        apiUrl = `https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=${encodeURIComponent(query)}`;
        responseKey = 'result';
        break;
      default:
        return res.status(400).json({
          creator: "Contact Gain",
          status: 400,
          success: false,
          error: "Invalid AI model specified"
        });
    }
    
    const aiResponse = await axios.get(apiUrl);
    
    if (aiResponse.data.success) {
      res.json({
        creator: "Contact Gain",
        status: 200,
        success: true,
        result: aiResponse.data[responseKey]
      });
    } else {
      res.status(400).json({
        creator: "Contact Gain",
        status: 400,
        success: false,
        error: "AI service returned an error"
      });
    }
  } catch (err) {
    console.error('AI API error:', err);
    res.status(500).json({
      creator: "Contact Gain",
      status: 500,
      success: false,
      error: "Failed to process AI request"
    });
  }
});

// Admin routes
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    const sessions = await Session.find().sort({ createdAt: -1 });
    const totalUsers = await User.countDocuments();
    const totalSessions = await Session.countDocuments();
    const totalContacts = await Contact.countDocuments();
    const totalDownloads = await Download.countDocuments();
    
    res.render('admin', {
      title: 'Admin Dashboard',
      users,
      sessions,
      totalUsers,
      totalSessions,
      totalContacts,
      totalDownloads
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load admin dashboard'
    });
  }
});

app.post('/admin/user/:id/toggle-suspend', isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    user.isSuspended = !user.isSuspended;
    user.suspendedAt = user.isSuspended ? new Date() : null;
    await user.save();
    
    res.json({ 
      success: true, 
      isSuspended: user.isSuspended,
      message: user.isSuspended ? 'User suspended successfully' : 'User unsuspended successfully'
    });
  } catch (err) {
    console.error('User suspension error:', err);
    res.status(500).json({ success: false, message: 'Failed to update user status' });
  }
});

app.post('/admin/user/:id/delete', isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Don't allow deleting super admin
    if (user.isSuperAdmin) {
      return res.status(403).json({ success: false, message: 'Cannot delete super admin' });
    }
    
    await User.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('User deletion error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete user' });
  }
});

// Socket.io setup
io.use((socket, next) => {
  // Authentication middleware for socket.io
  const token = socket.handshake.auth.token;
  if (token) {
    // Here you would verify the token
    // For simplicity, we'll just check if it's present
    return next();
  }
  next(new Error('Authentication error'));
});

io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Join user to their own room
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });
  
  // Join user to community chat room
  socket.on('join-community', (userId) => {
    socket.join('community');
    console.log(`User ${userId} joined community chat`);
  });
  
  // Send message
  socket.on('send-message', async (data) => {
    try {
      // Check for AI command
      if (data.content.startsWith('/GTP') || data.content.startsWith('@AI')) {
        const query = data.content.replace('/GTP', '').replace('@AI', '').trim();
        socket.emit('ai-request', {
          userId: data.userId,
          query: query,
          model: 'gpt'
        });
        return;
      }
      
      // Create message in database
      const message = new Message({
        userId: data.userId,
        content: data.content,
        recipient: data.recipient
      });
      
      await message.save();
      
      // Update last seen
      await User.findByIdAndUpdate(data.userId, { lastSeen: new Date() });
      
      // Broadcast message to recipient or community
      if (data.recipient) {
        // Private message
        io.to(data.recipient).emit('message', {
          ...message.toObject(),
          user: { 
            _id: data.userId,
            username: data.username,
            profile: data.profile
          }
        });
        
        // Also send to sender for confirmation
        socket.emit('message', {
          ...message.toObject(),
          user: { 
            _id: data.userId,
            username: data.username,
            profile: data.profile
          }
        });
      } else {
        // Community message
        io.to('community').emit('community-message', {
          ...message.toObject(),
          user: { 
            _id: data.userId,
            username: data.username,
            profile: data.profile
          }
        });
      }
      
      // Typing indicator - clear after message is sent
      io.to('community').emit('community-typing', {
        userId: data.userId,
        isTyping: false
      });
    } catch (err) {
      console.error('Message error:', err);
    }
  });
  
  // Typing indicator
  socket.on('typing', (data) => {
    if (data.recipient) {
      // Private chat typing
      io.to(data.recipient).emit('typing', {
        userId: data.userId,
        isTyping: data.isTyping
      });
    } else {
      // Community chat typing
      io.to('community').emit('community-typing', {
        userId: data.userId,
        isTyping: data.isTyping,
        username: data.username
      });
    }
  });
  
  // Message editing
  socket.on('edit-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (!message || message.userId.toString() !== data.userId) {
        return;
      }
      
      message.content = data.content;
      message.edited = true;
      await message.save();
      
      // Broadcast edited message
      if (message.recipient) {
        io.to(message.recipient.toString()).emit('message-updated', message);
        socket.emit('message-updated', message);
      } else {
        io.to('community').emit('community-message-updated', message);
      }
    } catch (err) {
      console.error('Edit message error:', err);
    }
  });
  
  // Message deletion
  socket.on('delete-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (!message || (message.userId.toString() !== data.userId && !data.isAdmin)) {
        return;
      }
      
      await Message.deleteOne({ _id: data.messageId });
      
      // Broadcast deletion
      if (message.recipient) {
        io.to(message.recipient.toString()).emit('message-deleted', data.messageId);
        socket.emit('message-deleted', data.messageId);
      } else {
        io.to('community').emit('community-message-deleted', data.messageId);
      }
    } catch (err) {
      console.error('Delete message error:', err);
    }
  });
  
  // Admin commands
  socket.on('admin-command', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user || !user.isAdmin) {
        return;
      }
      
      const command = data.command.toLowerCase();
      
      switch (command) {
        case '/clearchat':
          await Message.deleteMany({ recipient: null }); // Clear community chat
          io.to('community').emit('community-chat-cleared');
          break;
          
        case '/tagall':
          const users = await User.find({ isSuspended: false });
          let mentionText = '📢 @all: ';
          users.forEach(user => {
            mentionText += `@${user.username} `;
          });
          
          const message = new Message({
            userId: data.userId,
            content: mentionText,
            recipient: null
          });
          
          await message.save();
          
          io.to('community').emit('community-message', {
            ...message.toObject(),
            user: { 
              _id: data.userId,
              username: data.username,
              profile: data.profile
            }
          });
          break;
          
        case '/pin':
          // This would need implementation with a pinned messages system
          break;
          
        case '/unpin':
          // This would need implementation with a pinned messages system
          break;
          
        case '/ban':
          // This would send a list of users to ban
          const activeUsers = await User.find({ isSuspended: false, isSuperAdmin: false });
          socket.emit('show-ban-list', activeUsers);
          break;
          
        case '/help':
          const helpMessage = `
╭══〘〘 Contact Gain Bot 〙〙═⊷
┃❍ Prefix: /
┃❍ Owner: @${process.env.ADMIN_USERNAME}
┃❍ Plugins: 25
┃❍ Version: 5.0.0
┃❍ Uptime: ${formatUptime(process.uptime())}
┃❍ Time Now: ${moment().format('hh:mm:ss A')}
┃❍ Date Today: ${moment().format('DD/MM/YYYY')}
┃❍ Time Zone: Africa/Lagos
┃❍ Server RAM: ${formatMemoryUsage()}
┃❍ Commands:
┃❍ /clearchat - Clear chat
┃❍ /tagall - Tag all members
┃❍ /pin - Pin a message
┃❍ /unpin - Unpin a message
┃❍ /ban - Ban a user
┃❍ /help - Show this help
╰═════════════════════════════
          `;
          
          const helpMsg = new Message({
            userId: data.userId,
            content: helpMessage,
            recipient: null,
            isSystem: true
          });
          
          await helpMsg.save();
          
          io.to('community').emit('community-message', {
            ...helpMsg.toObject(),
            user: { 
              _id: 'system',
              username: 'System',
              profile: { name: 'System', profilePic: '/images/system.png' }
            }
          });
          break;
      }
    } catch (err) {
      console.error('Admin command error:', err);
    }
  });
  
  // Ban user
  socket.on('ban-user', async (data) => {
    try {
      const admin = await User.findById(data.adminId);
      if (!admin || !admin.isAdmin) {
        return;
      }
      
      const user = await User.findById(data.userId);
      if (user && !user.isSuperAdmin) {
        user.isSuspended = true;
        user.suspendedAt = new Date();
        await user.save();
        
        // Notify community
        const banMessage = new Message({
          userId: data.adminId,
          content: `User @${user.username} has been banned by ${admin.username}`,
          recipient: null,
          isSystem: true
        });
        
        await banMessage.save();
        
        io.to('community').emit('community-message', {
          ...banMessage.toObject(),
          user: { 
            _id: 'system',
            username: 'System',
            profile: { name: 'System', profilePic: '/images/system.png' }
          }
        });
      }
    } catch (err) {
      console.error('Ban user error:', err);
    }
  });
  
  // AI response
  socket.on('ai-response', (data) => {
    // Broadcast AI response to the appropriate room
    if (data.recipient) {
      io.to(data.recipient).emit('ai-response', data);
    } else {
      io.to('community').emit('ai-response', data);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Helper functions
function formatUptime(seconds) {
  const days = Math.floor(seconds / (24 * 3600));
  seconds %= 24 * 3600;
  const hours = Math.floor(seconds / 3600);
  seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  
  return `${days}d ${hours}h ${minutes}m ${secs}s`;
}

function formatMemoryUsage() {
  const total = (process.memoryUsage().heapTotal / 1024 / 1024).toFixed(2);
  const used = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2);
  return `${used} GB / ${total} GB`;
}

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
