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
const os = require('os');
const multer = require('multer');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

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
app.use(session({
  secret: process.env.SESSION_SECRET || 'e24c9bf7d58a4c3e9f1a6b8c7d3e2f4981a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.LINODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/public', express.static('public'));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images are allowed'), false);
  }
});

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
  },
  isPrivateMessagingRestricted: { type: Boolean, default: false }
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

const groupSchema = new mongoose.Schema({
  name: { type: String, default: 'Community Chat' },
  profilePic: String,
  description: { type: String, default: 'Welcome to the Contact Gain Community!' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  type: { type: String, enum: ['text', 'image'], default: 'text' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date },
  deleted: { type: Boolean, default: false },
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pinned: { type: Boolean, default: false },
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
});

const privateMessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  type: { type: String, enum: ['text', 'image'], default: 'text' },
  createdAt: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
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
  res.redirect('/login');
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
};

// Socket.IO Setup
const onlineUsers = {};
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.on('connection', (socket) => {
  const user = socket.request.user;
  if (!user) {
    socket.disconnect();
    return;
  }
  
  onlineUsers[user._id] = socket.id;
  user.lastSeen = new Date();
  user.save();
  
  socket.join('community-chat');
  
  socket.on('chat-message', async (data) => {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    if (urlRegex.test(data.content) && !user.isAdmin) {
      socket.emit('error', 'Links are not allowed for non-admins.');
      return;
    }
    
    const message = new Message({
      groupId: data.groupId || 'default-group',
      userId: user._id,
      content: data.content,
      type: data.type || 'text'
    });
    await message.save();
    
    io.to('community-chat').emit('chat-message', {
      user: { id: user._id, username: user.username, isAdmin: user.isAdmin, profile: user.profile },
      content: data.content,
      createdAt: message.createdAt,
      messageId: message._id,
      type: message.type
    });
  });
  
  socket.on('private-message', async (data) => {
    if (user.isPrivateMessagingRestricted && !user.isAdmin) {
      socket.emit('error', 'You are restricted from sending private messages.');
      return;
    }
    
    const recipientSocketId = onlineUsers[data.recipientId];
    const pm = new PrivateMessage({
      senderId: user._id,
      receiverId: data.recipientId,
      content: data.content,
      type: data.type || 'text'
    });
    await pm.save();
    
    const messageData = {
      sender: { id: user._id, username: user.username, profile: user.profile },
      content: data.content,
      createdAt: pm.createdAt,
      messageId: pm._id,
      type: pm.type
    };
    
    socket.emit('private-message', messageData);
    if (recipientSocketId) io.to(recipientSocketId).emit('private-message', messageData);
  });
  
  socket.on('delete-message', async (data) => {
    const message = await Message.findById(data.messageId);
    if (!message || (message.userId.toString() !== user._id.toString() && !user.isAdmin)) return;
    
    message.deleted = true;
    message.deletedBy = user.isAdmin ? user._id : null;
    await message.save();
    
    io.to('community-chat').emit('message-deleted', { messageId: data.messageId, deletedBy: user.isAdmin ? user._id : null });
  });
  
  socket.on('edit-message', async (data) => {
    const message = await Message.findById(data.messageId);
    if (!message || (message.userId.toString() !== user._id.toString() && !user.isAdmin)) return;
    
    message.content = data.content;
    message.updatedAt = new Date();
    await message.save();
    
    io.to('community-chat').emit('message-edited', { messageId: data.messageId, content: data.content });
  });
  
  socket.on('ai-request', async (data) => {
    const response = await getAiResponse(data.model, data.query);
    const formattedResponse = formatAiResponse(response, data.model);
    io.to('community-chat').emit('ai-response', {  formattedResponse);
  });
  
  socket.on('typing', (data) => {
    io.to(data.isPrivate ? `private-${[user._id, data.recipientId].sort().join('-')}` : 'community-chat').emit('typing', {
      user: { id: user._id, username: user.username },
      isTyping: data.isTyping,
      isPrivate: data.isPrivate,
      recipientId: data.recipientId
    });
  });
  
  socket.on('disconnect', () => {
    delete onlineUsers[user._id];
    user.lastSeen = new Date();
    user.save();
  });
});

// AI Response Handler
async function getAiResponse(model, query) {
  const apiMap = {
    gpt: `https://apis.davidcyriltech.my.id/ai/chatbot?query=${encodeURIComponent(query)}`,
    llama: `https://apis.davidcyriltech.my.id/ai/llama3?text=${encodeURIComponent(query)}`,
    deepseek: `https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=${encodeURIComponent(query)}`,
    gemini: `https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=${encodeURIComponent(query)}`,
    flux: `https://api.giftedtech.web.id/api/ai/fluximg?apikey=gifted&prompt=${encodeURIComponent(query)}`
  };
  
  try {
    const response = await fetch(apiMap[model] || apiMap['gpt']);
    const data = await response.json();
    return data.result || data.response || data.message || 'No response';
  } catch (error) {
    return 'Error fetching AI response';
  }
}

function formatAiResponse(response, model) {
  const uptime = process.uptime();
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);
  const now = new Date();
  const totalMem = os.totalmem() / (1024 * 1024 * 1024);
  const freeMem = os.freemem() / (1024 * 1024 * 1024);
  
  return `
    <div class="ai-response">
      <pre style="white-space: pre-wrap;">
╭══〘〘 𝙲𝙾𝙽𝚃𝙰𝙲𝚃 𝙶𝙰𝙸𝙽 〙〙═⊷
┃❍ Pʀᴇғɪx:   / 
┃❍ ᴏᴡɴᴇʀ:  @AiOfLautech
┃❍ Pʟᴜɢɪɴs:  20
┃❍ Vᴇʀsɪᴏɴ:  3.0.0
┃❍ Uᴘᴛɪᴍᴇ:  ${days}d ${hours}h ${minutes}m ${seconds}s
┃❍ Tɪᴍᴇ Nᴏᴡ:  ${now.toLocaleTimeString('en-US', { hour12: true })}
┃❍ Dᴀᴛᴇ Tᴏᴅᴀʏ:  ${now.toLocaleDateString('en-US')}
┃❍ Tɪᴍᴇ Zᴏɴᴇ:  ${Intl.DateTimeFormat().resolvedOptions().timeZone}
┃❍ Sᴇʀᴠᴇʀ Rᴀᴍ:  ${(totalMem - freeMem).toFixed(2)} GB/${totalMem.toFixed(2)} GB
╰═════════════════⊷

Powered by Contact Gain AI (${model.toUpperCase()}):
${response}

𝙲𝙾𝙼𝙼𝙰𝙽𝙳𝚂 𝙻𝙸𝚂𝚃:
╭─── 『 𝙰𝙸 』
✧ /gpt
✧ /llama
✧ /deepseek
✧ /gemini
✧ /flux
╰─────────────────◊
      </pre>
    </div>
  `;
}

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/terminal', isAuthenticated, async (req, res) => {
  const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
  const totalContacts = await Contact.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
  const totalSessions = sessions.filter(s => s.status === 'active').length;
  const totalDownloads = await Download.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
  const avgContacts = totalSessions > 0 ? (totalContacts / totalSessions).toFixed(1) : 0;
  
  res.render('terminal', { 
    user: req.user,
    sessions,
    stats: { totalContacts, totalSessions, avgContacts, totalDownloads }
  });
});

app.get('/admin', isAdmin, async (req, res) => {
  const stats = {
    totalUsers: await User.countDocuments(),
    totalSessions: await Session.countDocuments(),
    activeSessions: await Session.countDocuments({ status: 'active' }),
    totalDownloads: await Download.countDocuments(),
    succeededDownloads: await Download.countDocuments({ status: 'success' }),
    failedDownloads: await Download.countDocuments({ status: 'failed' }),
    expiredOrDeletedSessions: await Session.countDocuments({ $or: [{ status: 'expired' }, { status: 'deleted' }] }),
    totalContacts: await Contact.countDocuments(),
    sessionsWithWhatsapp: await Session.countDocuments({ whatsappLink: { $ne: null } })
  };
  const recentSessions = await Session.find().sort({ createdAt: -1 }).limit(5).populate('userId');
  const recentDownloads = await Download.find().sort({ timestamp: -1 }).limit(5);
  const users = await User.find();
  const sessions = await Session.find().sort({ createdAt: -1 });
  
  res.render('admin', { stats, recentSessions, recentDownloads, users, sessions });
});

app.get('/chat', isAuthenticated, async (req, res) => {
  let group = await Group.findOne({ name: 'Community Chat' });
  if (!group) {
    group = new Group({ name: 'Community Chat', members: [req.user._id], admins: [] });
    await group.save();
  }
  if (!group.members.includes(req.user._id)) {
    group.members.push(req.user._id);
    await group.save();
  }
  
  const messages = await Message.find({ groupId: group._id }).populate('userId');
  const onlineUserIds = Object.keys(onlineUsers);
  res.render('chat', { user: req.user, group, messages, onlineUsers: onlineUserIds });
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  const profileUser = await User.findById(req.params.userId);
  if (!profileUser) return res.status(404).send('User not found');
  const onlineUserIds = Object.keys(onlineUsers);
  res.render('profile', { user: req.user, profileUser, onlineUsers: onlineUserIds, currentUser: req.user });
});

app.get('/private-chat/:recipientId', isAuthenticated, async (req, res) => {
  const recipient = await User.findById(req.params.recipientId);
  if (!recipient) return res.status(404).send('User not found');
  const messages = await PrivateMessage.find({
    $or: [
      { senderId: req.user._id, receiverId: recipient._id },
      { senderId: recipient._id, receiverId: req.user._id }
    ]
  }).sort({ createdAt: 1 }).populate('senderId');
  res.render('private-chat', { user: req.user, recipient, messages });
});

app.post('/upload-profile-pic', isAuthenticated, upload.single('profilePic'), async (req, res) => {
  if (req.file) {
    req.user.profile = req.user.profile || {};
    req.user.profile.profilePic = `/public/uploads/${req.file.filename}`;
    await req.user.save();
  }
  res.redirect('/profile/' + req.user._id);
});

app.post('/update-profile', isAuthenticated, async (req, res) => {
  const { name, phone, bio } = req.body;
  req.user.profile = { ...req.user.profile, name, phone, bio };
  await req.user.save();
  res.redirect('/profile/' + req.user._id);
});

app.get('/session/:sessionId', async (req, res) => {
  const sessionData = await Session.findOne({ sessionId: req.params.sessionId });
  if (!sessionData) return res.status(404).send('Session not found.');
  if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
    sessionData.status = 'expired';
    await sessionData.save();
  }
  const msLeft = sessionData.expiresAt - Date.now();
  const totalSeconds = msLeft > 0 ? Math.floor(msLeft / 1000) : 0;
  const recommendedSessions = await Session.find({ 
    sessionId: { $ne: req.params.sessionId },
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
  const expiresAt = new Date(Date.now() + parseInt(timer) * 60 * 1000);
  const session = new Session({ userId: req.user._id, sessionId, groupName, whatsappLink, timer, expiresAt });
  await session.save();
  res.json({ sessionLink: `${req.protocol}://${req.get('host')}/session/${sessionId}` });
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
    vcfData += `BEGIN:VCARD\nVERSION:3.0\nFN:${contact.name}\nTEL;TYPE=CELL:${contact.phone}\nEND:VCARD\n`;
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

app.post('/admin/restrict-pm/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { isPrivateMessagingRestricted: true });
  res.redirect('/admin');
});

// Start Server
mongoose.connection.once('open', () => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
