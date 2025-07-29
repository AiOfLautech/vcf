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
const multer = require('multer');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.LINODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  isAdmin: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  profile: { name: String, phone: String, bio: String, profilePic: String },
  suspensionEnd: { type: Date },
  banEnd: { type: Date },
  restrictedPM: { type: Boolean, default: false }
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
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pinned: { type: Boolean, default: false }
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  profilePic: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  link: { type: String, unique: true }
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

// Default Group
async function createDefaultGroup() {
  const group = await Group.findOne({ name: 'Initial Group' });
  if (!group) {
    const newGroup = new Group({
      name: 'Initial Group',
      description: 'Default group for new users',
      members: [],
      link: `group-${crypto.randomBytes(4).toString('hex')}`
    });
    await newGroup.save();
    console.log('Default group created');
  }
}
createDefaultGroup();

// Passport Configuration
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: 'Incorrect username.' });

    if (user.status === 'banned' && user.banEnd && Date.now() < user.banEnd.getTime()) {
      const hoursLeft = Math.ceil((user.banEnd - Date.now()) / (1000 * 60 * 60));
      return done(null, false, { message: `Account banned for 72 hours. ${hoursLeft} hours remaining.` });
    } else if (user.status === 'suspended' && user.suspensionEnd && Date.now() < user.suspensionEnd.getTime()) {
      const hoursLeft = Math.ceil((user.suspensionEnd - Date.now()) / (1000 * 60 * 60));
      return done(null, false, { message: `Account suspended for 24 hours. ${hoursLeft} hours remaining.` });
    } else if (user.status !== 'active') {
      user.status = 'active';
      user.banEnd = null;
      user.suspensionEnd = null;
      await user.save();
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

// Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
};

// Server Start Time for Uptime
const startTime = Date.now();

// Socket.IO
io.on('connection', (socket) => {
  console.log('User connected');

  socket.on('join', async (userId) => {
    socket.join(userId);
    await User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
    io.emit('online-users', await User.find({ lastSeen: { $gt: Date.now() - 300000 } }).select('_id'));
  });

  socket.on('chat-message', async (data) => {
    const user = await User.findById(data.userId);
    if (!user || (data.content.includes('http') && !user.isAdmin)) return;

    const message = new Message({
      userId: data.userId,
      content: data.content,
      isPrivate: data.isPrivate,
      recipient: data.recipient
    });
    await message.save();

    const messageData = {
      _id: message._id,
      user: { id: user._id, username: user.username, isAdmin: user.isAdmin, profile: user.profile },
      content: data.content,
      createdAt: message.createdAt,
      isPrivate: data.isPrivate,
      recipient: data.recipient
    };

    if (data.isPrivate) {
      let conversation = await Conversation.findOne({ participants: { $all: [data.userId, data.recipient] } });
      if (!conversation) {
        conversation = new Conversation({ participants: [data.userId, data.recipient], lastMessage: message._id });
      } else {
        conversation.lastMessage = message._id;
        conversation.updatedAt = Date.now();
      }
      await conversation.save();
      io.to(data.recipient).to(data.userId).emit('private-message', messageData);
    } else {
      io.emit('chat-message', messageData);
    }
  });

  socket.on('delete-message', async (data) => {
    const message = await Message.findById(data.messageId);
    if (!message || (message.userId.toString() !== data.userId && !data.isAdmin)) return;

    message.deleted = true;
    message.deletedBy = data.isAdmin ? data.userId : null;
    await message.save();

    io.emit('message-deleted', { messageId: data.messageId, deletedByAdmin: data.isAdmin });
  });

  socket.on('edit-message', async (data) => {
    const message = await Message.findById(data.messageId);
    if (!message || (message.userId.toString() !== data.userId && !data.isAdmin)) return;

    message.content = data.content;
    message.edited = true;
    await message.save();

    io.emit('message-edited', { messageId: data.messageId, content: data.content });
  });

  socket.on('pin-message', async (data) => {
    const message = await Message.findById(data.messageId);
    if (!message || !data.isAdmin) return;

    message.pinned = !message.pinned;
    await message.save();

    io.emit('message-pinned', { messageId: data.messageId, pinned: message.pinned });
  });

  socket.on('typing', (data) => {
    if (data.isPrivate) {
      socket.to(data.recipientId).emit('private-typing', { senderId: data.userId, isTyping: data.isTyping });
    } else {
      socket.broadcast.emit('community-typing', data);
    }
  });

  socket.on('ai-request', async (data) => {
    const user = await User.findById(data.userId);
    if (!user) return;

    const aiModels = {
      chatgpt: 'https://apis.davidcyriltech.my.id/ai/chatbot?query=',
      llama: 'https://apis.davidcyriltech.my.id/ai/llama3?text=',
      deepseekv3: 'https://apis.davidcyriltech.my.id/ai/deepseek-v3?text=',
      deepseekr1: 'https://apis.davidcyriltech.my.id/ai/deepseek-r1?text=',
      metaai: 'https://apis.davidcyriltech.my.id/ai/metaai?text=',
      gpt4: 'https://apis.davidcyriltech.my.id/ai/gpt4?text=',
      claude: 'https://apis.davidcyriltech.my.id/ai/claudeSonnet?text=',
      uncensor: 'https://apis.davidcyriltech.my.id/ai/uncensor?text=',
      pixtral: 'https://apis.davidcyriltech.my.id/ai/pixtral?text=',
      gemma: 'https://apis.davidcyriltech.my.id/ai/gemma?text=',
      qvq: 'https://apis.davidcyriltech.my.id/ai/qvq?text=',
      qwen2: 'https://apis.davidcyriltech.my.id/ai/qwen2Coder?text=',
      gemini: 'https://api.giftedtech.web.id/api/ai/geminiai?apikey=gifted&q=',
      geminipro: 'https://api.giftedtech.web.id/api/ai/geminiaipro?apikey=gifted&q=',
      gptturbo: 'https://api.giftedtech.web.id/api/ai/gpt-turbo?apikey=gifted&q=',
      letmegpt: 'https://api.giftedtech.web.id/api/ai/letmegpt?apikey=gifted&query=',
      simsimi: 'https://api.giftedtech.web.id/api/ai/simsimi?apikey=gifted&query=',
      luminai: 'https://api.giftedtech.web.id/api/ai/luminai?apikey=gifted&query=',
      wwdgpt: 'https://api.giftedtech.web.id/api/ai/wwdgpt?apikey=gifted&prompt='
    };

    let url = aiModels[data.model] + encodeURIComponent(data.query);
    try {
      const response = await axios.get(url);
      let aiResponse = response.data.result || response.data.message || response.data.response || 'No response';

      const uptime = process.uptime();
      const days = Math.floor(uptime / (24 * 3600));
      const hours = Math.floor((uptime % (24 * 3600)) / 3600);
      const minutes = Math.floor((uptime % 3600) / 60);
      const seconds = Math.floor(uptime % 60);

      const formattedResponse = `
        <div class="ai-response">
          <pre style="font-family: monospace; white-space: pre-wrap;">
╭══〘〘 Contact Gain AI 〙〙═⊷
┃❍ Pʀᴇғɪx:   / 
┃❍ ᴏᴡɴᴇʀ:  @AiOfLautech
┃❍ Pʟᴜɢɪɴs:  20
┃❍ Vᴇʀsɪᴏɴ:  2.0.0
┃❍ Uᴘᴛɪᴍᴇ:  ${days}d ${hours}h ${minutes}m ${seconds}s
┃❍ Tɪᴍᴇ Nᴏᴡ:  ${new Date().toLocaleTimeString('en-US', { hour12: true })}
┃❍ Dᴀᴛᴇ Tᴏᴅᴀʏ:  ${new Date().toLocaleDateString('en-US')}
┃❍ Tɪᴍᴇ Zᴏɴᴇ:  Africa/Lagos
┃❍ Sᴇʀᴠᴇʀ Rᴀᴍ:  74.81 GB/125.77 GB
╰═════════════════⊷

Response:
${aiResponse}
          </pre>
          <div class="ai-footer">Powered by Contact Gain</div>
        </div>
      `;
      socket.emit('ai-response', { content: formattedResponse });
    } catch (err) {
      socket.emit('ai-response', { content: 'Error processing request.' });
    }
  });

  socket.on('disconnect', () => console.log('User disconnected'));
});

// Routes
app.get('/', (req, res) => res.render('index'));

app.get('/login', (req, res) => res.render('login'));
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: false }));

app.get('/signup', (req, res) => res.render('signup'));
app.post('/signup', async (req, res) => {
  try {
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) return res.render('signup', { error: 'Username exists' });
    if (req.body.password !== req.body.confirmPassword) return res.render('signup', { error: 'Passwords do not match' });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.render('signup', { error: 'Signup failed' });
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error(err);
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

app.get('/terminal', isAuthenticated, async (req, res) => {
  const sessions = await Session.find({ userId: req.user._id }).sort({ createdAt: -1 });
  const totalContacts = await Contact.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } });
  res.render('terminal', {
    user: req.user,
    sessions,
    stats: {
      totalContacts,
      totalSessions: sessions.filter(s => s.status === 'active').length,
      avgContacts: sessions.length > 0 ? (totalContacts / sessions.length).toFixed(1) : 0,
      totalDownloads: await Download.countDocuments({ sessionId: { $in: sessions.map(s => s.sessionId) } })
    }
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
  res.render('admin', {
    stats,
    recentSessions: await Session.find().sort({ createdAt: -1 }).limit(5).populate('userId'),
    users: await User.find()
  });
});

app.get('/chat', isAuthenticated, async (req, res) => {
  let group = await Group.findOne({ name: 'Initial Group' });
  if (!group) {
    await createDefaultGroup();
    group = await Group.findOne({ name: 'Initial Group' });
  }
  if (!group.members.includes(req.user._id)) {
    group.members.push(req.user._id);
    await group.save();
  }
  res.render('chat', {
    user: req.user,
    group,
    messages: await Message.find({ isPrivate: false }).sort({ createdAt: -1 }).limit(50).populate('userId').populate('repliedTo'),
    onlineUsers: await User.find({ lastSeen: { $gt: Date.now() - 300000 } })
  });
});

app.get('/group/:groupId', isAuthenticated, async (req, res) => {
  const group = await Group.findById(req.params.groupId).populate('members');
  if (!group) return res.status(404).send('Group not found');
  res.render('group-info', { user: req.user, group });
});

app.get('/profile/:userId', isAuthenticated, async (req, res) => {
  const profileUser = await User.findById(req.params.userId);
  if (!profileUser) return res.status(404).send('User not found');
  res.render('profile', { currentUser: req.user, profileUser });
});

app.get('/edit-profile', isAuthenticated, (req, res) => res.render('edit-profile', { user: req.user }));
app.post('/edit-profile', isAuthenticated, upload.single('profilePic'), async (req, res) => {
  const { name, phone, bio } = req.body;
  const profilePic = req.file ? `/uploads/${req.file.filename}` : req.user.profile.profilePic;
  await User.findByIdAndUpdate(req.user._id, { profile: { name, phone, bio, profilePic } });
  res.redirect('/profile/' + req.user._id);
});

app.get('/private-chat/:userId', isAuthenticated, async (req, res) => {
  const recipient = await User.findById(req.params.userId);
  if (!recipient) return res.status(404).send('User not found');
  const messages = await Message.find({
    $or: [
      { userId: req.user._id, recipient: recipient._id, isPrivate: true },
      { userId: recipient._id, recipient: req.user._id, isPrivate: true }
    ]
  }).sort({ createdAt: 1 }).populate('userId');
  res.render('private-chat', { user: req.user, recipient, messages });
});

app.get('/conversations', isAuthenticated, async (req, res) => {
  const conversations = await Conversation.find({ participants: req.user._id })
    .populate('participants')
    .populate('lastMessage')
    .sort({ updatedAt: -1 });
  res.render('conversations', { user: req.user, conversations });
});

app.get('/session/:sessionId', async (req, res) => {
  const sessionData = await Session.findOne({ sessionId: req.params.sessionId });
  if (!sessionData) return res.status(404).send('Session not found');
  if (Date.now() > sessionData.expiresAt && sessionData.status !== 'expired') {
    sessionData.status = 'expired';
    await sessionData.save();
  }
  res.render('session', {
    groupName: sessionData.groupName,
    sessionId: sessionData.sessionId,
    whatsappLink: sessionData.whatsappLink,
    totalSeconds: Math.max(Math.floor((sessionData.expiresAt - Date.now()) / 1000), 0),
    recommendedSessions: await Session.find({ sessionId: { $ne: req.params.sessionId }, expiresAt: { $gt: new Date() }, status: 'active' }).sort({ createdAt: -1 }).limit(5)
  });
});

app.post('/create-session', isAuthenticated, async (req, res) => {
  const { groupName, timer, whatsappLink } = req.body;
  if (!groupName || !timer) return res.status(400).json({ error: 'Group name and timer required' });
  const sessionId = 'GDT' + crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6);
  const expiresAt = new Date(Date.now() + parseInt(timer) * 60 * 1000);
  const session = new Session({ userId: req.user._id, sessionId, groupName, whatsappLink, timer, expiresAt });
  await session.save();
  res.json({ sessionLink: `${req.protocol}://${req.get('host')}/session/${sessionId}` });
});

app.post('/session/:sessionId/contact', async (req, res) => {
  const { name, phone } = req.body;
  const sessionData = await Session.findOne({ sessionId: req.params.sessionId });
  if (!sessionData || Date.now() > sessionData.expiresAt) return res.status(400).json({ error: 'Session ended' });
  const contact = new Contact({ sessionId: req.params.sessionId, name, phone });
  await contact.save();
  sessionData.contactCount += 1;
  await sessionData.save();
  res.json({ success: true });
});

app.post('/admin/suspend-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'suspended', suspensionEnd: new Date(Date.now() + 24 * 60 * 60 * 1000) });
  res.redirect('/admin');
});

app.post('/admin/ban-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'banned', banEnd: new Date(Date.now() + 72 * 60 * 60 * 1000) });
  res.redirect('/admin');
});

app.post('/admin/unsuspend-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'active', suspensionEnd: null });
  res.redirect('/admin');
});

app.post('/admin/unban-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { status: 'active', banEnd: null });
  res.redirect('/admin');
});

app.post('/admin/promote-user/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { isAdmin: true });
  res.redirect('/admin');
});

app.post('/admin/restrict-pm/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { restrictedPM: true });
  res.redirect('/admin');
});

app.post('/admin/unrestrict-pm/:userId', isAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.userId, { restrictedPM: false });
  res.redirect('/admin');
});

app.post('/admin/remove-from-group/:userId', isAdmin, async (req, res) => {
  const group = await Group.findOne({ name: 'Initial Group' });
  group.members = group.members.filter(m => m.toString() !== req.params.userId);
  await group.save();
  res.redirect('/admin');
});

// Start Server
const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`Server running on port ${PORT}`));
