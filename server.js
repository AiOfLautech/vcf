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
  .then(() => console.log('MongoDB connected successfully'))
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

const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);

// Create Default Group
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

    if (user.status === 'banned') {
      return done(null, false, { message: 'Your account has been banned.' });
    }

    if (user.status === 'suspended') {
      const suspensionEnd = new Date(user.updatedAt.getTime() + (72 * 60 * 60 * 1000));
      if (Date.now() < suspensionEnd.getTime()) {
        return done(null, false, { message: 'Your account is suspended.' });
      } else {
        user.status = 'active';
        await user.save();
      }
    }

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
  res.redirect('/login');
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.redirect('/login');
};

// Socket.io Configuration
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('join', (userId) => {
    socket.join(userId);
    User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
  });

  socket.on('chat-message', async (data) => {
    try {
      const user = await User.findById(data.userId);
      if (!user) return;

      const message = new Message({
        userId: data.userId,
        content: data.content,
        isPrivate: false
      });
      await message.save();

      io.emit('chat-message', {
        user: { id: user._id, username: user.username, isAdmin: user.isAdmin, profile: user.profile },
        content: data.content,
        createdAt: new Date()
      });
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('private-message', async (data) => {
    try {
      const sender = await User.findById(data.senderId);
      if (!sender) return;

      const message = new Message({
        userId: data.senderId,
        recipient: data.recipientId,
        content: data.content,
        isPrivate: true
      });
      await message.save();

      let conversation = await Conversation.findOne({
        participants: { $all: [data.senderId, data.recipientId] }
      });
      if (!conversation) {
        conversation = new Conversation({
          participants: [data.senderId, data.recipientId],
          lastMessage: message._id
        });
      } else {
        conversation.lastMessage = message._id;
        conversation.updatedAt = new Date();
      }
      await conversation.save();

      io.to(data.recipientId).to(data.senderId).emit('private-message', {
        sender: { id: sender._id, username: sender.username, profile: sender.profile },
        content: data.content,
        createdAt: new Date()
      });
    } catch (err) {
      console.error('Error sending private message:', err);
    }
  });

  socket.on('private-typing', (data) => {
    socket.to(data.recipientId).emit('private-typing', {
      senderId: data.senderId,
      isTyping: data.isTyping
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/terminal', isAuthenticated, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.user._id });
    res.render('terminal', { user: req.user, sessions });
  } catch (err) {
    console.error('Terminal error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalSessions: await Session.countDocuments(),
      activeSessions: await Session.countDocuments({ status: 'active' }),
      totalDownloads: await Download.countDocuments()
    };
    res.render('admin', { stats, user: req.user });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/chat', isAuthenticated, async (req, res) => {
  try {
    let group = await Group.findOne({ name: 'Contact Gain Community' });
    if (!group) {
      await createDefaultGroup();
      group = await Group.findOne({ name: 'Contact Gain Community' });
    }
    const messages = await Message.find({ isPrivate: false }).populate('userId');
    res.render('chat', { user: req.user, group, messages });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/group/:groupId', isAuthenticated, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId).populate('members');
    if (!group) return res.status(404).send('Group not found');
    res.render('group-info', { user: req.user, group });
  } catch (err) {
    console.error('Group info error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  try {
    const profileUser = await User.findById(req.params.userId);
    if (!profileUser) return res.status(404).send('User not found');
    res.render('profile', { currentUser: req.user, profileUser });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/edit-profile', isAuthenticated, (req, res) => {
  res.render('edit-profile', { user: req.user });
});

app.post('/edit-profile', isAuthenticated, async (req, res) => {
  try {
    const { name, phone, bio, profilePic } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      'profile.name': name,
      'profile.phone': phone,
      'profile.bio': bio,
      'profile.profilePic': profilePic
    });
    res.redirect(`/profile/${req.user._id}`);
  } catch (err) {
    console.error('Edit profile error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  try {
    const recipient = await User.findById(req.params.userId);
    if (!recipient) return res.status(404).send('User not found');
    const messages = await Message.find({
      $or: [
        { userId: req.user._id, recipient: recipient._id, isPrivate: true },
        { userId: recipient._id, recipient: req.user._id, isPrivate: true }
      ]
    }).populate('userId');
    res.render('private-chat', { user: req.user, recipient, messages });
  } catch (err) {
    console.error('Private chat error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/conversations', isAuthenticated, async (req, res) => {
  try {
    const conversations = await Conversation.find({ participants: req.user._id })
      .populate('participants')
      .populate('lastMessage');
    res.render('conversations', { user: req.user, conversations });
  } catch (err) {
    console.error('Conversations error:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/session/:sessionId', async (req, res) => {
  try {
    const sessionData = await Session.findOne({ sessionId: req.params.sessionId });
    if (!sessionData) return res.status(404).send('Session not found');
    if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
      sessionData.status = 'expired';
      await sessionData.save();
    }
    const msLeft = sessionData.expiresAt - Date.now();
    const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;
    res.render('session', { session: sessionData, totalSeconds });
  } catch (err) {
    console.error('Session error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/session/:sessionId/contact', async (req, res) => {
  const { name, phone } = req.body;
  const { sessionId } = req.params;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone are required.' });
  try {
    const sessionData = await Session.findOne({ sessionId });
    if (!sessionData || sessionData.status !== 'active') return res.status(400).json({ error: 'Session is not active.' });
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
    if (!sessionData) return res.status(404).send('Session not found');
    sessionData.downloadCount += 1;
    await sessionData.save();
    const contacts = await Contact.find({ sessionId });
    let vcfData = '';
    contacts.forEach(contact => {
      vcfData += `BEGIN:VCARD\nVERSION:3.0\nFN:${contact.name}\nTEL;TYPE=CELL:${contact.phone}\nEND:VCARD\n`;
    });
    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${sessionData.groupName}.vcf"`);
    res.send(vcfData || 'No contacts added.');
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/delete-session/:sessionId', isAuthenticated, async (req, res) => {
  try {
    await Session.findOneAndDelete({ sessionId: req.params.sessionId, userId: req.user._id });
    res.redirect('/terminal');
  } catch (err) {
    console.error('Delete session error:', err);
    res.status(500).send('Internal server error');
  }
});

// Admin Routes
app.post('/admin/delete-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.userId);
    res.redirect('/admin');
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/admin/suspend-user/:userId', isAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { status: 'suspended', updatedAt: new Date() });
    res.redirect('/admin');
  } catch (err) {
    console.error('Suspend user error:', err);
    res.status(500).send	parseInt('Internal server error');
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

// User Authentication Routes
app.post('/signup', async (req, res) => {
  try {
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) return res.render('signup', { error: 'Username already exists' });
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.render('signup', { error: 'User creation failed' });
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

// Create Session
app.post('/create-session', isAuthenticated, async (req, res) => {
  const { groupName, timer } = req.body;
  if (!groupName || !timer) return res.status(400).json({ error: 'Group name and timer are required.' });
  const sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
  const expiresAt = new Date(Date.now() + parseInt(timer) * 60 * 1000);
  try {
    const session = new Session({ userId: req.user._id, sessionId, groupName, timer, expiresAt });
    await session.save();
    res.json({ sessionLink: `${req.protocol}://${req.get('host')}/session/${sessionId}` });
  } catch (err) {
    console.error('Session creation error:', err);
    res.status(500).json({ error: 'Failed to create session.' });
  }
});

// Start Server
mongoose.connection.once('open', () => {
  createDefaultGroup();
  const PORT = process.env.PORT || 3000;
  http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});