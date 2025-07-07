require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIo = require('socket.io');
const sharedsession = require('express-socket.io-session');
const multer = require('multer');
const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL || 'mongodb+srv://hephzibarsamuel:sHFaJEdlFlDCaQwb@contact-gain.cbtkalw.mongodb.net/?retryWrites=true&w=majority&appName=Contact-Gain', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'e24c9bf7d58a4c3e9f1a6b8c7d3e2f4981a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.LINODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Multer Setup for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  profilePicture: { type: String, default: '/uploads/default-profile.png' },
  bio: { type: String, default: '' },
  isOnline: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  phone: { type: String, default: '' }
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
  text: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  timestamp: { type: Date, default: Date.now },
  isEdited: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  deletedByAdmin: { type: Boolean, default: false },
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  isPinned: { type: Boolean, default: false },
  imageUrl: { type: String }
});

const privateMessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  imageUrl: { type: String }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, default: 'Community Chat' },
  description: { type: String, default: 'Welcome to the Contact Gain community!' },
  profilePicture: { type: String, default: '/uploads/default-group.png' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Download = mongoose.model('Download', downloadSchema);
const Message = mongoose.model('Message', messageSchema);
const PrivateMessage = mongoose.model('PrivateMessage', privateMessageSchema);
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

// Authentication Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
};

// Socket.io Setup
io.use(sharedsession(sessionMiddleware, { autoSave: true }));

io.on('connection', async (socket) => {
  const user = socket.handshake.session.user;
  if (!user) {
    socket.disconnect();
    return;
  }

  await User.findByIdAndUpdate(user._id, { isOnline: true });
  io.emit('user status', { userId: user._id, isOnline: true });

  let group = await Group.findOne();
  if (!group) {
    group = new Group({ members: [user._id] });
    await group.save();
  } else if (!group.members.includes(user._id)) {
    group.members.push(user._id);
    await group.save();
  }

  socket.join('group');

  socket.on('chat message', async (data) => {
    if (!user.isAdmin && /https?:\/\/\S+/.test(data.text)) {
      socket.emit('error', 'You are not allowed to send links.');
      return;
    }
    const message = new Message({
      text: data.text,
      sender: user._id,
      replyTo: data.replyTo,
      imageUrl: data.imageUrl
    });
    await message.save();
    const populatedMessage = await Message.findById(message._id).populate('sender replyTo');
    io.to('group').emit('chat message', populatedMessage);
  });

  socket.on('edit message', async (data) => {
    const message = await Message.findById(data.id);
    if (message.sender.toString() === user._id || user.isAdmin) {
      message.text = data.text;
      message.isEdited = true;
      await message.save();
      io.to('group').emit('message edited', message);
    }
  });

  socket.on('delete message', async (data) => {
    const message = await Message.findById(data.id);
    if (message.sender.toString() === user._id || user.isAdmin) {
      message.isDeleted = true;
      message.deletedByAdmin = user.isAdmin;
      await message.save();
      io.to('group').emit('message deleted', { id: message._id, deletedByAdmin: user.isAdmin });
    }
  });

  socket.on('pin message', async (data) => {
    if (user.isAdmin) {
      const message = await Message.findById(data.id);
      message.isPinned = !message.isPinned;
      await message.save();
      io.to('group').emit('message pinned', message);
    }
  });

  socket.on('typing', () => {
    socket.to('group').emit('user typing', { userId: user._id, username: user.username });
  });

  socket.on('private message', async (data) => {
    const room = [user._id, data.receiver].sort().join('-');
    socket.join(room);
    const message = new PrivateMessage({
      sender: user._id,
      receiver: data.receiver,
      text: data.text,
      imageUrl: data.imageUrl
    });
    await message.save();
    const populatedMessage = await PrivateMessage.findById(message._id).populate('sender receiver');
    io.to(room).emit('private message', populatedMessage);
  });

  socket.on('ai command', async (data) => {
    const parts = data.text.slice(4).trim().split(' ');
    const model = parts[0].toLowerCase();
    const query = parts.slice(1).join(' ');
    let apiUrl, responseKey;
    const apis = {
      'chatgpt': { url: `https://apis.davidcyriltech.my.id/ai/chatbot?query=${encodeURIComponent(query)}`, key: 'result' },
      'llama': { url: `https://apis.davidcyriltech.my.id/ai/llama3?text=${encodeURIComponent(query)}`, key: 'message' },
      'deepseek-v3': { url: `https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=${encodeURIComponent(query)}`, key: 'response' },
      'deepseek-r1': { url: `https://apis.davidcyriltech.my.id/ai/deepseek-r1?text=${encodeURIComponent(query)}`, key: 'response' },
      'meta-ai': { url: `https://apis.davidcyriltech.my.id/ai/metaai?text=${encodeURIComponent(query)}`, key: 'response' },
      'gpt4': { url: `https://apis.davidcyriltech.my.id/ai/gpt4?text=${encodeURIComponent(query)}`, key: 'message' },
      'claude': { url: `https://apis.davidcyriltech.my.id/ai/claudeSonnet?text=${encodeURIComponent(query)}`, key: 'response' },
      'uncensored': { url: `https://apis.davidcyriltech.my.id/ai/uncensor?text=${encodeURIComponent(query)}`, key: 'response' },
      'pixtral': { url: `https://apis.davidcyriltech.my.id/ai/pixtral?text=${encodeURIComponent(query)}`, key: 'response' },
      'gemma': { url: `https://apis.davidcyriltech.my.id/ai/gemma?text=${encodeURIComponent(query)}`, key: 'response' },
      'qvq': { url: `https://apis.davidcyriltech.my.id/ai/qvq?text=${encodeURIComponent(query)}`, key: 'response' },
      'qwen2': { url: `https://apis.davidcyriltech.my.id/ai/qwen2Coder?text=${encodeURIComponent(query)}`, key: 'response' },
      'gemini': { url: `https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=${encodeURIComponent(query)}`, key: 'result' },
      'gemini-pro': { url: `https://api.giftedtech.web.id/api/ai/geminiaipro?apikey=gifted&q=${encodeURIComponent(query)}`, key: 'result' },
      'gpt-turbo': { url: `https://api.giftedtech.web.id/api/ai/gpt-turbo?apikey=gifted&q=${encodeURIComponent(query)}`, key: 'result' },
      'letme': { url: `https://api.giftedtech.web.id/api/ai/letmegpt?apikey=gifted&query=${encodeURIComponent(query)}`, key: 'result' },
      'simsimi': { url: `https://api.giftedtech.web.id/api/ai/simsimi?apikey=gifted&query=${encodeURIComponent(query)}`, key: 'result' },
      'lumin': { url: `https://api.giftedtech.web.id/api/ai/luminai?apikey=gifted&query=${encodeURIComponent(query)}`, key: 'result' },
      'wwd': { url: `https://api.giftedtech.web.id/api/ai/wwdgpt?apikey=gifted&prompt=${encodeURIComponent(query)}`, key: 'result' }
    };

    if (!apis[model]) {
      socket.emit('error', 'Invalid AI model specified.');
      return;
    }

    const { url, key } = apis[model];
    try {
      const response = await fetch(url);
      const data = await response.json();
      const aiResponse = data[key];
      const now = new Date();
      const uptime = process.uptime();
      const days = Math.floor(uptime / 86400);
      const hours = Math.floor((uptime % 86400) / 3600);
      const minutes = Math.floor((uptime % 3600) / 60);
      const seconds = Math.floor(uptime % 60);
      const uptimeStr = `${days}d ${hours}h ${minutes}m ${seconds}s`;
      const timeNow = now.toLocaleTimeString('en-US', { hour12: true });
      const dateToday = now.toLocaleDateString('en-US');
      const timeZone = 'Africa/Lagos';

      const formattedResponse = `╭══〘〘 Contact Gain AI 〙〙═⊷
┃❍ Uᴘᴛɪᴍᴇ: ${uptimeStr}
┃❍ Tɪᴍᴇ Nᴏᴡ: ${timeNow}
┃❍ Dᴀᴛᴇ Tᴏᴅᴀʏ: ${dateToday}
┃❍ Tɪᴍᴇ Zᴏɴᴇ: ${timeZone}
╰═════════════════⊷

${aiResponse}`;

      const aiMessage = new Message({
        text: formattedResponse,
        sender: 'AI',
        isAI: true
      });
      await aiMessage.save();
      io.to('group').emit('chat message', aiMessage);
    } catch (err) {
      socket.emit('error', 'Failed to get AI response.');
    }
  });

  socket.on('disconnect', async () => {
    await User.findByIdAndUpdate(user._id, { isOnline: false });
    io.emit('user status', { userId: user._id, isOnline: false });
  });
});

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/terminal', isAuthenticated, async (req, res) => {
  const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
  const totalContacts = await Contact.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
  const totalSessions = sessions.length;
  const activeSessions = sessions.filter(s => s.status === 'active').length;
  const totalDownloads = await Download.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
  const avgContacts = totalSessions > 0 ? (totalContacts / totalSessions).toFixed(1) : 0;
  res.render('terminal', { user: req.user, sessions, stats: { totalContacts, totalSessions: activeSessions, avgContacts, totalDownloads } });
});

app.get('/admin', isAdmin, async (req, res) => {
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
    stats: { totalUsers, totalSessions, activeSessions, totalDownloads, succeededDownloads, failedDownloads, expiredOrDeletedSessions, totalContacts, sessionsWithWhatsapp },
    recentSessions, recentDownloads, users, sessions
  });
});

app.get('/chat', isAuthenticated, async (req, res) => {
  const messages = await Message.find().populate('sender replyTo').sort({ timestamp: 1 });
  const group = await Group.findOne().populate('members admins');
  const users = await User.find();
  res.render('chat', { user: req.user, messages, group, users });
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  const profileUser = await User.findById(req.params.userId);
  if (!profileUser) return res.status(404).send('User not found');
  res.render('profile', { user: req.user, profileUser });
});

app.get('/profile/edit', isAuthenticated, (req, res) => {
  res.render('profile', { user: req.user, profileUser: req.user, isEdit: true });
});

app.post('/profile/edit', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
  const updates = { bio: req.body.bio, phone: req.body.phone };
  if (req.file) updates.profilePicture = `/uploads/${req.file.filename}`;
  await User.findByIdAndUpdate(req.user._id, updates);
  res.redirect(`/profile/${req.user._id}`);
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  const receiver = await User.findById(req.params.userId);
  if (!receiver) return res.status(404).send('User not found');
  const messages = await PrivateMessage.find({
    $or: [
      { sender: req.user._id, receiver: req.params.userId },
      { sender: req.params.userId, receiver: req.user._id }
    ]
  }).populate('sender receiver').sort({ timestamp: 1 });
  const users = await User.find();
  res.render('private-chat', { user: req.user, receiver, messages, users });
});

app.post('/upload', isAuthenticated, upload.single('image'), (req, res) => {
  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ imageUrl });
});

app.get('/session/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  const sessionData = await Session.findOne({ sessionId });
  if (!sessionData) return res.status(404).send('Session not found.');
  if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
    sessionData.status = 'expired';
    await sessionData.save();
  }
  const msLeft = sessionData.expiresAt - Date.now();
  const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;
  const recommendedSessions = await Session.find({ sessionId: { $ne: sessionId }, expiresAt: { $gt: new Date() }, status: 'active' }).sort({ createdAt: -1 }).limit(5);
  res.render('session', { groupName: sessionData.groupName, sessionId: sessionData.sessionId, whatsappLink: sessionData.whatsappLink, totalSeconds, recommendedSessions });
});

app.post('/delete-session/:sessionId', isAuthenticated, async (req, res) => {
  const session = await Session.findOne({ sessionId: req.params.sessionId, userId: req.user._id });
  if (!session) return res.status(404).send('Session not found');
  await session.remove();
  res.redirect('/terminal');
});

app.post('/admin/delete-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndDelete(req.params.userId);
  res.redirect('/admin');
});

app.post('/admin/delete-session/:sessionId', isAdmin, async (req, res) => {
  await Session.findOneAndDelete({ sessionId: req.params.sessionId });
  res.redirect('/admin');
});

app.post('/signup', async (req, res) => {
  const existingUser = await User.findOne({ username: req.body.username });
  if (existingUser) return res.render('signup', { error: 'Username already exists' });
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new User({ username: req.body.username, password: hashedPassword });
  await user.save();
  res.redirect('/login');
});

app.post('/login', passport.authenticate('local', { successRedirect: '/chat', failureRedirect: '/login', failureFlash: false }));

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

app.get('/admin/login', (req, res) => res.render('admin-login'));

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('admin-login', { error: 'Invalid credentials' });
  }
});

app.post('/create-session', isAuthenticated, async (req, res) => {
  const { groupName, timer, whatsappLink } = req.body;
  if (!groupName || !timer) return res.status(400).json({ error: 'Group name and timer are required.' });
  if (isNaN(timer) || timer <= 0 || timer > 1440) return res.status(400).json({ error: 'Timer must be a positive number up to 1440 minutes.' });
  const sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
  const now = Date.now();
  const expiresAt = new Date(now + parseInt(timer) * 60 * 1000);
  const session = new Session({ userId: req.user._id, sessionId, groupName, whatsappLink, timer, expiresAt });
  await session.save();
  const sessionLink = `${req.protocol}://${req.get('host')}/session/${sessionId}`;
  res.json({ sessionLink });
});

app.post('/session/:sessionId/contact', async (req, res) => {
  const { name, phone } = req.body;
  const { sessionId } = req.params;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone are required.' });
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
});

app.get('/session/:sessionId/download', async (req, res) => {
  const { sessionId } = req.params;
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
  const download = new Download({ sessionId, status: 'success' });
  await download.save();
  res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
  res.send(vcfData || 'No contacts were added.');
});

app.post('/admin/suspend-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'suspended' });
  res.redirect('/admin');
});

app.post('/admin/ban-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'banned' });
  res.redirect('/admin');
});

app.post('/admin/unsuspend-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
  res.redirect('/admin');
});

app.post('/admin/unban-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'active' });
  res.redirect('/admin');
});

app.post('/admin/promote-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { isAdmin: true });
  res.redirect('/admin');
});

// Start Server
mongoose.connection.once('open', () => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
