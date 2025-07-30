require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const MongoStore = require('connect-mongo');
const flash = require('connect-flash');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const moment = require('moment');
const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
  createDefaultGroup();
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(flash());

// Session configuration
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

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Models
const User = require('./models/User');
const Session = require('./models/Session');
const Contact = require('./models/Contact');
const Message = require('./models/Message');
const Download = require('./models/Download');
const Group = require('./models/Group');

// Passport Local Strategy
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
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

// AI Models Configuration
const aiModels = {
  gpt: 'https://apis.davidcyriltech.my.id/ai/chatbot?query=',
  llama: 'https://apis.davidcyriltech.my.id/ai/llama3?text=',
  deepseek: 'https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=',
  deepseekr1: 'https://apis.davidcyriltech.my.id/ai/deepseek-r1?text=',
  metaai: 'https://apis.davidcyriltech.my.id/ai/metaai?text=',
  gpt4: 'https://apis.davidcyriltech.my.id/ai/gpt4?text=',
  claude: 'https://apis.davidcyriltech.my.id/ai/claudeSonnet?text=',
  uncensored: 'https://apis.davidcyriltech.my.id/ai/uncensor?text=',
  pixtral: 'https://apis.davidcyriltech.my.id/ai/pixtral?text=',
  gemma: 'https://apis.davidcyriltech.my.id/ai/gemma?text=',
  qvq: 'https://apis.davidcyriltech.my.id/ai/qvq?text=',
  queen2: 'https://apis.davidcyriltech.my.id/ai/qwen2Coder?text=',
  gemini: 'https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=',
  wwdgpt: 'https://api.giftedtech.web.id/api/ai/wwdgpt?apikey=gifted&prompt=',
  stableDiffusion: 'https://api.giftedtech.web.id/api/ai/sd?apikey=gifted&prompt=',
  text2img: 'https://api.giftedtech.web.id/api/ai/text2img?apikey=gifted&prompt='
};

// Helper function to get AI response
async function getAIResponse(model, query) {
  try {
    const url = aiModels[model] + encodeURIComponent(query);
    const response = await axios.get(url);
    
    let aiResponse = '';
    
    switch(model) {
      case 'gpt':
        aiResponse = response.data.result;
        break;
      case 'llama':
      case 'deepseek':
      case 'deepseekr1':
      case 'metaai':
      case 'claude':
      case 'uncensored':
      case 'pixtral':
      case 'gemma':
      case 'qvq':
      case 'queen2':
        aiResponse = response.data.response || response.data.message;
        break;
      case 'gpt4':
        aiResponse = response.data.message;
        break;
      case 'gemini':
      case 'wwdgpt':
        aiResponse = response.data.result;
        break;
      default:
        aiResponse = response.data;
    }
    
    return {
      creator: "Contact Gain",
      status: 200,
      success: true,
      result: aiResponse
    };
  } catch (error) {
    console.error('AI API error:', error);
    return {
      creator: "Contact Gain",
      status: 500,
      success: false,
      error: "Failed to get AI response. Please try again later."
    };
  }
}

// EJS setup
app.set('view engine', 'ejs');
app.set('views', './views');

// Middleware to make user available to all views
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Routes
app.get('/', (req, res) => {
  if (req.user) {
    res.redirect('/dashboard');
  } else {
    res.render('landing');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { 
    title: 'Login | Contact Gain',
    message: req.flash('error')
  });
});

app.post('/login', 
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/signup', (req, res) => {
  res.render('signup', { 
    title: 'Sign Up | Contact Gain',
    message: req.flash('error')
  });
});

app.post('/signup', async (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      req.flash('error', 'Username or email already exists');
      return res.redirect('/signup');
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      email,
      profile: {
        name: username,
        bio: "Hello, I'm using Contact Gain!"
      }
    });
    
    await user.save();
    
    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Error occurred during registration');
    res.redirect('/signup');
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    req.flash('success_msg', 'You are logged out');
    res.redirect('/login');
  });
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
    const groups = await Group.find({ members: req.user._id }).sort({ createdAt: -1 });
    
    // Update user's last seen
    await User.findByIdAndUpdate(req.user._id, { lastSeen: new Date() });
    
    res.render('dashboard', { 
      title: 'Dashboard | Contact Gain',
      sessions,
      groups
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

app.get('/admin/login', (req, res) => {
  res.render('admin-login', { 
    title: 'Admin Login | Contact Gain',
    message: req.flash('error')
  });
});

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if user is admin
  if ((username === process.env.ADMIN_USERNAME || username === process.env.SUPER_ADMIN_USERNAME) && 
      (password === process.env.ADMIN_PASSWORD || password === process.env.SUPER_ADMIN_PASSWORD)) {
    
    // Create admin session
    req.session.isAdmin = true;
    req.session.isSuperAdmin = (username === process.env.SUPER_ADMIN_USERNAME);
    req.session.username = username;
    
    return res.redirect('/admin');
  }
  
  req.flash('error', 'Invalid admin credentials');
  res.redirect('/admin/login');
});

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    const sessions = await Session.find().sort({ createdAt: -1 });
    const messages = await Message.find().sort({ createdAt: -1 }).limit(50);
    const groups = await Group.find().populate('members').sort({ createdAt: -1 });
    
    res.render('admin', { 
      title: 'Admin Dashboard | Contact Gain',
      users,
      sessions,
      messages,
      groups,
      isSuperAdmin: req.session.isSuperAdmin
    });
  } catch (err) {
    console.error(err);
    res.redirect('/admin/login');
  }
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin/login');
  });
});

app.get('/profile/:id', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).render('error', {
        title: 'User Not Found',
        message: 'The user you are looking for does not exist.'
      });
    }
    
    // Get user's sessions
    const sessions = await Session.find({ userId: user._id }).sort({ createdAt: -1 });
    
    res.render('profile', { 
      title: `${user.username} | Contact Gain`,
      profileUser: user,
      sessions
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

app.get('/edit-profile', isAuthenticated, (req, res) => {
  res.render('edit-profile', { 
    title: 'Edit Profile | Contact Gain'
  });
});

app.post('/update-profile', isAuthenticated, async (req, res) => {
  try {
    const { name, phone, bio, profilePic } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      profile: { 
        name, 
        phone, 
        bio, 
        profilePic 
      }
    });
    
    res.redirect('/profile/' + req.user._id);
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    // Get all users for private messaging
    const users = await User.find({ _id: { $ne: req.user._id } });
    
    // Update user's last seen
    await User.findByIdAndUpdate(req.user._id, { lastSeen: new Date() });
    
    res.render('chat', { 
      title: 'Community Chat | Contact Gain',
      users
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
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
    
    // Update user's last seen
    await User.findByIdAndUpdate(req.user._id, { lastSeen: new Date() });
    
    res.render('chat', { 
      title: `Chat with ${recipient.username} | Contact Gain`,
      privateChat: true,
      recipient,
      messages
    });
  } catch (err) {
    console.error('Private chat error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/conversations', isAuthenticated, async (req, res) => {
  try {
    // Get all conversations for the user
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
              { $eq: ["$userId", req.user._id] },
              "$recipient",
              "$userId"
            ]
          },
          lastMessage: { $first: "$$ROOT" }
        }
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "recipient"
        }
      },
      {
        $unwind: "$recipient"
      },
      {
        $sort: { "lastMessage.createdAt": -1 }
      }
    ]);
    
    res.render('conversations', { 
      title: 'Conversations | Contact Gain',
      conversations
    });
  } catch (err) {
    console.error('Conversations error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/api', (req, res) => {
  res.render('api', { 
    title: 'API Documentation | Contact Gain'
  });
});

app.get('/terminal', isAuthenticated, (req, res) => {
  res.render('terminal', { 
    title: 'AI Terminal | Contact Gain'
  });
});

// API Endpoints
app.post('/api/create-session', isAuthenticated, async (req, res) => {
  try {
    const { groupName, whatsappGroup, timer } = req.body;
    
    if (!groupName) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    const sessionId = uuidv4().substring(0, 8).toUpperCase();
    const expiresAt = new Date(Date.now() + (timer || 60) * 60 * 1000);
    
    const session = new Session({
      sessionId,
      userId: req.user._id,
      groupName,
      whatsappGroup,
      timer: timer || 60,
      expiresAt
    });
    
    await session.save();
    
    res.json({
      sessionLink: `${req.protocol}://${req.get('host')}/session/${sessionId}`,
      sessionId
    });
  } catch (err) {
    console.error('Session creation error:', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/session/:sessionId/contact', async (req, res) => {
  try {
    const { name, phone } = req.body;
    const { sessionId } = req.params;
    
    if (!name || !phone) {
      return res.status(400).json({ success: false, error: 'Name and phone are required' });
    }
    
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    // Check if timer has expired
    if (new Date() > sessionData.expiresAt) {
      return res.status(400).json({ success: false, error: 'Session timer has expired' });
    }
    
    const contact = new Contact({
      sessionId,
      name,
      phone
    });
    
    await contact.save();
    
    res.json({ success: true });
  } catch (err) {
    console.error('Contact addition error:', err);
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
      vcfData += `BEGIN:VCARD\n`;
      vcfData += `VERSION:3.0\n`;
      vcfData += `FN:${contact.name}\n`;
      vcfData += `TEL;TYPE=CELL:${contact.phone}\n`;
      vcfData += `END:VCARD\n`;
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

// Admin API Endpoints
app.post('/admin/api/ban-user', isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    await User.findByIdAndUpdate(userId, { isBanned: true, bannedAt: new Date() });
    io.emit('userBanned', { userId });
    res.json({ success: true });
  } catch (err) {
    console.error('Ban user error:', err);
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

app.post('/admin/api/unban-user', isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    await User.findByIdAndUpdate(userId, { isBanned: false, bannedAt: null });
    io.emit('userUnbanned', { userId });
    res.json({ success: true });
  } catch (err) {
    console.error('Unban user error:', err);
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

app.post('/admin/api/suspend-user', isAdmin, async (req, res) => {
  try {
    const { userId, duration } = req.body;
    const suspendedUntil = new Date(Date.now() + duration * 60 * 1000);
    
    await User.findByIdAndUpdate(userId, { 
      isSuspended: true, 
      suspendedUntil,
      suspendedAt: new Date()
    });
    
    io.emit('userSuspended', { userId, suspendedUntil });
    res.json({ success: true });
  } catch (err) {
    console.error('Suspend user error:', err);
    res.status(500).json({ error: 'Failed to suspend user' });
  }
});

app.post('/admin/api/unsuspend-user', isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    await User.findByIdAndUpdate(userId, { 
      isSuspended: false, 
      suspendedUntil: null,
      suspendedAt: null
    });
    
    io.emit('userUnsuspended', { userId });
    res.json({ success: true });
  } catch (err) {
    console.error('Unsuspend user error:', err);
    res.status(500).json({ error: 'Failed to unsuspend user' });
  }
});

app.post('/admin/api/delete-message', isAdmin, async (req, res) => {
  try {
    const { messageId } = req.body;
    await Message.findByIdAndUpdate(messageId, { isDeleted: true });
    io.emit('messageDeleted', { messageId });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.post('/admin/api/clear-chat', isAdmin, async (req, res) => {
  try {
    await Message.deleteMany({});
    io.emit('chatCleared');
    res.json({ success: true });
  } catch (err) {
    console.error('Clear chat error:', err);
    res.status(500).json({ error: 'Failed to clear chat' });
  }
});

// AI API Endpoints
app.post('/api/ai/gpt', async (req, res) => {
  try {
    const { query } = req.body;
    const response = await getAIResponse('gpt', query);
    res.json(response);
  } catch (err) {
    console.error('GPT API error:', err);
    res.status(500).json({
      creator: "Contact Gain",
      status: 500,
      success: false,
      error: "Failed to get AI response"
    });
  }
});

app.post('/api/ai/llama', async (req, res) => {
  try {
    const { query } = req.body;
    const response = await getAIResponse('llama', query);
    res.json(response);
  } catch (err) {
    console.error('Llama API error:', err);
    res.status(500).json({
      creator: "Contact Gain",
      status: 500,
      success: false,
      error: "Failed to get AI response"
    });
  }
});

app.post('/api/ai/deepseek', async (req, res) => {
  try {
    const { query } = req.body;
    const response = await getAIResponse('deepseek', query);
    res.json(response);
  } catch (err) {
    console.error('Deepseek API error:', err);
    res.status(500).json({
      creator: "Contact Gain",
      status: 500,
      success: false,
      error: "Failed to get AI response"
    });
  }
});

// Socket.io for real-time chat
io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Join community chat room
  socket.join('community');
  
  // Handle typing indicator
  socket.on('typing', (data) => {
    socket.broadcast.to('community').emit('typing', {
      userId: data.userId,
      username: data.username
    });
  });
  
  // Handle stop typing
  socket.on('stopTyping', (data) => {
    socket.broadcast.to('community').emit('stopTyping', {
      userId: data.userId
    });
  });
  
  // Handle message sending
  socket.on('sendMessage', async (data) => {
    try {
      const { userId, content, recipient, isPrivate } = data;
      
      // Check if user is banned or suspended
      const user = await User.findById(userId);
      if (user.isBanned || (user.isSuspended && new Date() < user.suspendedUntil)) {
        socket.emit('messageError', { error: 'You are not allowed to send messages' });
        return;
      }
      
      // Create message
      const message = new Message({
        userId,
        content,
        recipient: recipient || null,
        isPrivate: !!recipient
      });
      
      await message.save();
      
      // AI command handling
      if (content.startsWith('/GTP') || content.startsWith('@AI')) {
        const query = content.replace('/GTP', '').replace('@AI', '').trim();
        const response = await getAIResponse('gpt', query);
        
        const aiMessage = new Message({
          userId: 'ai-bot',
          content: response.result,
          isAI: true,
          recipient: recipient || null,
          isPrivate: !!recipient
        });
        
        await aiMessage.save();
        io.to('community').emit('newMessage', aiMessage);
      }
      
      // Admin commands
      if (user.isAdmin && content.startsWith('/')) {
        if (content.startsWith('/clearchat')) {
          await Message.deleteMany({});
          io.to('community').emit('chatCleared');
        } else if (content.startsWith('/tagall')) {
          const users = await User.find({ isBanned: false, isSuspended: false });
          const taggedUsers = users.map(u => `@${u.username}`).join(' ');
          const tagMessage = new Message({
            userId: userId,
            content: `Tagging all members: ${taggedUsers}`,
            isSystem: true
          });
          await tagMessage.save();
          io.to('community').emit('newMessage', tagMessage);
        } else if (content.startsWith('/pin')) {
          // Get message ID from reply
          const messageId = content.split(' ')[1];
          await Message.findByIdAndUpdate(messageId, { isPinned: true });
          io.to('community').emit('messagePinned', { messageId });
        } else if (content.startsWith('/unpin')) {
          // Get message ID from reply
          const messageId = content.split(' ')[1];
          await Message.findByIdAndUpdate(messageId, { isPinned: false });
          io.to('community').emit('messageUnpinned', { messageId });
        } else if (content.startsWith('/delete')) {
          // Get message ID from reply
          const messageId = content.split(' ')[1];
          await Message.findByIdAndUpdate(messageId, { isDeleted: true });
          io.to('community').emit('messageDeleted', { messageId });
        } else if (content.startsWith('/ban')) {
          // Get username from command
          const username = content.split(' ')[1];
          const targetUser = await User.findOne({ username });
          if (targetUser) {
            await User.findByIdAndUpdate(targetUser._id, { isBanned: true, bannedAt: new Date() });
            io.to('community').emit('userBanned', { userId: targetUser._id });
            
            // Notify the banned user
            const banMessage = new Message({
              userId: 'system',
              content: `You have been banned from the community chat`,
              isSystem: true
            });
            await banMessage.save();
            io.to(targetUser._id.toString()).emit('newMessage', banMessage);
          }
        }
      }
      
      // Regular message
      io.to('community').emit('newMessage', message);
      
      // Private message handling
      if (recipient) {
        io.to(recipient.toString()).emit('newMessage', message);
      }
    } catch (err) {
      console.error('Message error:', err);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });
  
  // Handle message editing
  socket.on('editMessage', async (data) => {
    try {
      const { messageId, newContent, userId } = data;
      
      // Check if user owns the message
      const message = await Message.findById(messageId);
      if (message.userId.toString() !== userId) {
        socket.emit('editError', { error: 'You can only edit your own messages' });
        return;
      }
      
      // Update message
      message.content = newContent;
      message.isEdited = true;
      message.editedAt = new Date();
      await message.save();
      
      io.to('community').emit('messageEdited', {
        messageId,
        newContent,
        editedAt: message.editedAt
      });
    } catch (err) {
      console.error('Edit message error:', err);
      socket.emit('editError', { error: 'Failed to edit message' });
    }
  });
  
  // Handle message deletion
  socket.on('deleteMessage', async (data) => {
    try {
      const { messageId, userId } = data;
      
      // Check if user owns the message or is admin
      const message = await Message.findById(messageId);
      const user = await User.findById(userId);
      
      if (message.userId.toString() !== userId && !user.isAdmin) {
        socket.emit('deleteError', { error: 'You can only delete your own messages' });
        return;
      }
      
      // Update message as deleted
      message.isDeleted = true;
      await message.save();
      
      io.to('community').emit('messageDeleted', { messageId });
    } catch (err) {
      console.error('Delete message error:', err);
      socket.emit('deleteError', { error: 'Failed to delete message' });
    }
  });
  
  // Handle message reply
  socket.on('replyMessage', async (data) => {
    try {
      const { messageId, replyContent, userId, recipient } = data;
      
      // Get original message
      const originalMessage = await Message.findById(messageId);
      if (!originalMessage) {
        socket.emit('replyError', { error: 'Original message not found' });
        return;
      }
      
      // Create reply message
      const replyMessage = new Message({
        userId,
        content: replyContent,
        replyTo: messageId,
        recipient: recipient || null,
        isPrivate: !!recipient
      });
      
      await replyMessage.save();
      
      // Format the reply for display
      const replyNotification = new Message({
        userId: 'system',
        content: `${originalMessage.userId === userId ? 'You' : `@${originalMessage.username}`} replied: ${replyContent}`,
        isSystem: true
      });
      
      await replyNotification.save();
      
      io.to('community').emit('newMessage', replyMessage);
      io.to('community').emit('newMessage', replyNotification);
    } catch (err) {
      console.error('Reply message error:', err);
      socket.emit('replyError', { error: 'Failed to reply to message' });
    }
  });
  
  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected');
    socket.leave('community');
  });
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error', 'Please log in to view this resource');
  res.redirect('/login');
}

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (req.session.isAdmin) {
    return next();
  }
  req.flash('error', 'You do not have permission to view this page');
  res.redirect('/');
}

// Create default group if none exists
async function createDefaultGroup() {
  try {
    const count = await Group.countDocuments();
    if (count === 0) {
      const defaultGroup = new Group({
        name: 'Community Chat',
        description: 'Main community chat for all users',
        isPublic: true
      });
      await defaultGroup.save();
      console.log('Default group created');
    }
  } catch (err) {
    console.error('Error creating default group:', err);
  }
}

// Start Server
mongoose.connection.once('open', () => {
  createDefaultGroup();
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
