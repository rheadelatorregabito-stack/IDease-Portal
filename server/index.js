const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.options('*', cors({ origin: true, credentials: true }));
app.use(bodyParser.json());

const sessions = new Map();
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

function hashPassword(password, salt = null) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, usedSalt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2$${usedSalt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const parts = stored.split('$');
    if (parts.length !== 3) return false;
    const [, salt, expectedHash] = parts;
    const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return computedHash === expectedHash;
  }
  return password === stored;
}

function createAdminSession(admin) {
  const token = `admin-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  sessions.set(token, { admin, token, createdAt: new Date().toISOString(), expiresAt });
  return token;
}

function getAdminSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function parseAuthorizationToken(req) {
  const header = req.headers['authorization'] || req.headers['x-admin-token'];
  if (!header) return null;
  if (header.toString().toLowerCase().startsWith('bearer ')) {
    return header.toString().slice(7).trim();
  }
  return header.toString().trim();
}

function optionalAdminAuth(req, res, next) {
  const token = parseAuthorizationToken(req);
  if (token) {
    const session = getAdminSession(token);
    if (!session) {
      return res.status(401).json({ error: 'unauthorized', message: 'Admin token invalid or expired.' });
    }
    req.adminSession = session;
    req.adminUser = session.admin;
  }
  return next();
}

function authenticateAdmin(req, res, next) {
  const token = parseAuthorizationToken(req);
  const session = getAdminSession(token);
  if (!session) {
    return res.status(401).json({ error: 'unauthorized', message: 'Admin token invalid or missing.' });
  }
  req.adminSession = session;
  req.adminUser = session.admin;
  return next();
}

// In-memory presence store: userId -> timestamp (ms)
const presence = new Map();
const PRESENCE_THRESHOLD_MS = 60000; // 60s

app.post('/presence/heartbeat', (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'missing userId' });
  const now = Date.now();
  presence.set(userId.toString(), now);
  return res.json({ ok: true, userId, lastSeen: new Date(now).toISOString() });
});

app.get('/presence/:userId', (req, res) => {
  const userId = req.params.userId;
  const t = presence.get(userId);
  if (!t) return res.json({ userId, online: false, lastSeen: null });
  const online = (Date.now() - t) < PRESENCE_THRESHOLD_MS;
  return res.json({ userId, online, lastSeen: new Date(t).toISOString() });
});

app.get('/presence', (req, res) => {
  const out = [];
  for (const [userId, t] of presence.entries()) {
    out.push({ userId, lastSeen: new Date(t).toISOString(), online: (Date.now() - t) < PRESENCE_THRESHOLD_MS });
  }
  res.json(out);
});

// In-memory notification store for IDEAS activity events.
const notifications = [];

// In-memory admin user store for basic authentication.
const admins = [
  { id: 'admin-001', username: 'admin', password: 'admin123', displayName: 'IDEase Admin', secretCode: 'ADMIN2026', role: 'admin' },
  { id: 'superadmin', username: 'superadmin', password: 'supersecure', displayName: 'Super Admin', secretCode: 'ADMIN2026', role: 'superadmin' }
];

// In-memory admin requests store for superadmin approval workflow.
const adminRequests = [];

// In-memory request store for IDEAS request lifecycle.
const requests = [];
// In-memory audit log for admin actions
const auditLogs = [];

function findRequestById(requestId) {
  return requests.find((req) => req.id === requestId) || null;
}

function normalizeName(name) {
  return (name || '').toString().trim().replace(/\s+/g, ' ').toLowerCase();
}

function createRequestRecord(data) {
  const now = new Date().toISOString();
  const fullName = data.fullName || data.studentName || 'Student';
  const record = {
    id: data.id || `REQ-${Date.now()}`,
    studentId: (data.studentId || data.studentId || data.userId || 'unknown').toString(),
    studentName: data.studentName || fullName,
    fullName,
    type: data.type || 'Student ID',
    status: data.status || 'Submitted',
    createdAt: data.createdAt || now,
    updatedAt: now,
    photoFilename: data.photoFilename || data.photoName || '',
    createdBy: data.createdBy || data.userId || 'student',
    rejectionReason: data.rejectionReason || null,
    details: data.details || ''
  };
  requests.unshift(record);
  return record;
}

function updateRequestStatusRecord(requestId, newStatus, additionalData = {}) {
  const request = findRequestById(requestId);
  if (!request) return null;
  request.status = newStatus;
  request.updatedAt = new Date().toISOString();
  Object.assign(request, additionalData);

  if (newStatus === 'Processing') {
    request.processingStartedAt = request.processingStartedAt || new Date().toISOString();
  }
  if (newStatus === 'Ready' || newStatus === 'Completed') {
    request.completedAt = new Date().toISOString();
  }
  if (newStatus === 'Rejected') {
    request.rejectedAt = new Date().toISOString();
  }

  return request;
}

function logAdminAction(action, details = {}) {
  const entry = {
    id: `AUDIT-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    action,
    details,
    timestamp: new Date().toISOString()
  };
  auditLogs.unshift(entry);
  console.log('[AUDIT]', entry);
  return entry;
}

function isActiveRequest(status) {
  const lower = (status || '').toLowerCase();
  return ['submitted', 'verification', 'processing', 'ready'].includes(lower);
}

function hasActiveRequest(studentId) {
  if (!studentId) return false;
  return requests.some((req) => req.studentId === studentId.toString() && isActiveRequest(req.status));
}

function hasActiveDuplicateRequest(studentId, fullName) {
  if (!studentId || !fullName) return false;
  const normalizedFullName = normalizeName(fullName);
  return requests.some((req) => {
    const matchesStudent = req.studentId === studentId.toString();
    const matchesName = normalizeName(req.fullName || req.studentName) === normalizedFullName;
    return matchesStudent && matchesName && isActiveRequest(req.status);
  });
}

// Middleware to prevent students creating overlapping active requests
function enforceSingleActiveRequest(req, res, next) {
  const payload = req.body || {};
  const studentId = payload.studentId;
  const fullName = payload.fullName || payload.studentName;
  if (!studentId) return res.status(400).json({ error: 'missing required request data' });

  if (!fullName) {
    return res.status(400).json({ error: 'missing required request data', message: 'Student ID and full name are required.' });
  }

  // Allow admins to create requests on behalf of students
  if (payload.createdBy && payload.createdBy === 'admin') return next();

  if (hasActiveRequest(studentId)) {
    return res.status(409).json({
      error: 'active_request_exists',
      message: 'You already have an active request. Please wait for completion or update if rejected.'
    });
  }

  if (hasActiveDuplicateRequest(studentId, fullName)) {
    return res.status(409).json({
      error: 'duplicate_active_request',
      message: 'You already have an active request. Please wait for completion or update if rejected.'
    });
  }
  return next();
}

function createRequestNotificationEvent(request, type, extra = {}) {
  const eventType = type;
  const titles = {
    'request.new': 'New ID Request Submitted',
    'request.verification': 'Request Verification Started',
    'request.processing': 'Request Processing',
    'request.ready': 'Request Ready',
    'request.completed': 'Request Completed',
    'request.rejected': 'Request Rejected'
  };
  const messages = {
    'request.new': 'Your ID request has been received and is now under review.',
    'request.verification': 'Your request is now under verification.',
    'request.processing': 'Your request is now being processed.',
    'request.ready': 'Your request has been completed and is ready.',
    'request.completed': 'Your request has been completed successfully.',
    'request.rejected': 'Your request has been rejected.'
  };
  const tones = {
    'request.new': 'orange',
    'request.verification': 'blue',
    'request.processing': 'blue',
    'request.ready': 'green',
    'request.completed': 'green',
    'request.rejected': 'red'
  };
  const icons = {
    'request.new': 'fa-file-circle-plus',
    'request.verification': 'fa-shield-check',
    'request.processing': 'fa-spinner',
    'request.ready': 'fa-circle-check',
    'request.completed': 'fa-circle-check',
    'request.rejected': 'fa-circle-xmark'
  };

  const event = {
    userId: request.studentId,
    type: eventType,
    category: 'Request Updates',
    title: titles[eventType] || 'Request Update',
    message: extra.message || messages[eventType] || 'Your request status changed.',
    details: extra.details || `Your request ${request.id} is now ${request.status}.`,
    tone: tones[eventType] || 'gray',
    icon: icons[eventType] || 'fa-bell',
    sourceId: request.id,
    timestamp: new Date().toISOString(),
    status: 'unread',
    request: {
      id: request.id,
      studentId: request.studentId,
      status: request.status,
      updatedAt: request.updatedAt
    }
  };

  createNotification(event);
  broadcast(event);

  const statusPayload = {
    type: 'requestStatusUpdate',
    requestId: request.id,
    studentId: request.studentId,
    status: request.status,
    updatedBy: extra.updatedBy || request.updatedBy || 'system',
    timestamp: new Date().toISOString(),
    request: { id: request.id, studentId: request.studentId, status: request.status, updatedAt: request.updatedAt }
  };
  broadcast(statusPayload);

  return event;
}

const ADMIN_SECRET_CODE = 'ADMIN2026';

app.post('/api/admin/login', (req, res) => {
  const { username, password, secretCode } = req.body || {};
  if (!username || !password || !secretCode) {
    return res.status(400).json({ error: 'missing_credentials', message: 'Username, password, and secret code are all required.' });
  }

  const admin = admins.find((entry) => entry.username === username.toString().trim());
  if (!admin) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid admin username or password.' });
  }

  if (admin.secretCode !== secretCode) {
    return res.status(401).json({ error: 'invalid_secret_code', message: 'Invalid admin secret code.' });
  }

  if (!verifyPassword(password, admin.passwordHash || admin.password)) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid admin username or password.' });
  }

  const token = createAdminSession(admin);
  const responsePayload = {
    ok: true,
    token,
    redirect: '/admin-dashboard.html',
    user: {
      id: admin.id,
      username: admin.username,
      displayName: admin.displayName,
      role: admin.role || 'admin',
      accountType: 'admin'
    }
  };

  logAdminAction('admin_login', { username: admin.username, adminId: admin.id });
  return res.status(200).json(responsePayload);
});

app.get('/api/admin/me', authenticateAdmin, (req, res) => {
  return res.json({ ok: true, user: req.adminUser });
});

app.post('/api/admin/signup', (req, res) => {
  const { username, password, role, displayName, secretCode } = req.body || {};

  if (secretCode !== ADMIN_SECRET_CODE) {
    return res.status(401).json({ error: 'invalid_secret_code', message: 'Invalid admin secret code.' });
  }

  // Validate required fields
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'missing_fields', message: 'Username, password, and role are required.' });
  }

  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters long.' });
  }
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must contain uppercase letters and numbers.' });
  }

  // Check if username already exists (in current admins or pending requests)
  const usernameExists = admins.some(a => a.username.toLowerCase() === username.toLowerCase());
  const pendingRequest = adminRequests.some(ar => ar.username.toLowerCase() === username.toLowerCase() && ar.status === 'pending');
  
  if (usernameExists) {
    return res.status(409).json({ error: 'username_taken', message: 'Username already exists.' });
  }
  if (pendingRequest) {
    return res.status(409).json({ error: 'pending_request', message: 'A registration request for this username is already pending.' });
  }

  // Validate role
  if (!['admin', 'superadmin'].includes(role)) {
    return res.status(400).json({ error: 'invalid_role', message: 'Invalid role specified.' });
  }

  // Superadmin role cannot be self-registered
  if (role === 'superadmin') {
    return res.status(403).json({ error: 'forbidden', message: 'Superadmin role must be assigned by existing superadmin.' });
  }

  // Create active admin account immediately so the registration form can be used.
  const passwordHash = hashPassword(password);
  const newAdmin = {
    id: 'admin-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    username: username.trim(),
    passwordHash,
    displayName: displayName || username,
    role: role,
    createdAt: new Date().toISOString(),
    createdBy: 'self_signup'
  };

  admins.push(newAdmin);

  const requestId = 'admin-req-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  const adminRequest = {
    id: requestId,
    username: newAdmin.username,
    passwordHash,
    displayName: newAdmin.displayName,
    role: newAdmin.role,
    status: 'approved',
    requestedAt: newAdmin.createdAt,
    approvedAt: new Date().toISOString(),
    approvedBy: 'self_signup',
    adminId: newAdmin.id,
    ipAddress: req.ip || 'unknown'
  };

  adminRequests.push(adminRequest);
  logAdminAction('admin_signup_auto_approved', { username: newAdmin.username, role: newAdmin.role, requestId });

  return res.status(201).json({
    ok: true,
    message: 'Admin account created successfully. Please log in with your new credentials.',
    admin: {
      id: newAdmin.id,
      username: newAdmin.username,
      displayName: newAdmin.displayName,
      role: newAdmin.role
    }
  });
});

// Admin requests management (for superadmin approval workflow)
app.get('/api/admin/requests', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can view admin requests.' });
  }
  return res.json(adminRequests);
});

app.post('/api/admin/requests/:id/approve', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can approve admin requests.' });
  }

  const requestId = req.params.id;
  const adminReq = adminRequests.find(r => r.id === requestId);
  if (!adminReq) {
    return res.status(404).json({ error: 'not_found', message: 'Admin request not found.' });
  }

  // Check if username already taken (shouldn't happen, but safety check)
  if (admins.some(a => a.username.toLowerCase() === adminReq.username.toLowerCase())) {
    return res.status(409).json({ error: 'username_taken', message: 'Username was already created by another request.' });
  }

  // Create the actual admin account
  const newAdmin = {
    id: 'admin-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    username: adminReq.username,
    passwordHash: adminReq.passwordHash || hashPassword(adminReq.password || ''),
    displayName: adminReq.displayName,
    role: adminReq.role || 'admin',
    createdAt: new Date().toISOString(),
    createdBy: req.adminUser.username
  };

  admins.push(newAdmin);

  // Update request status
  adminReq.status = 'approved';
  adminReq.approvedAt = new Date().toISOString();
  adminReq.approvedBy = req.adminUser.username;
  adminReq.adminId = newAdmin.id; // Link to created admin account
  
  logAdminAction('admin_request_approved', { 
    requestId, 
    username: adminReq.username, 
    approvedBy: req.adminUser.username, 
    newAdminId: newAdmin.id 
  });
  
  return res.json({ 
    ok: true, 
    message: 'Admin account created successfully.',
    adminRequest: adminReq,
    newAdmin: { id: newAdmin.id, username: newAdmin.username, displayName: newAdmin.displayName }
  });
});

app.post('/api/admin/requests/:id/reject', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can reject admin requests.' });
  }

  const requestId = req.params.id;
  const adminReq = adminRequests.find(r => r.id === requestId);
  if (!adminReq) {
    return res.status(404).json({ error: 'not_found', message: 'Admin request not found.' });
  }

  const reason = (req.body && req.body.reason) || 'No reason provided';
  adminReq.status = 'rejected';
  adminReq.rejectedAt = new Date().toISOString();
  adminReq.rejectedBy = req.adminUser.username;
  adminReq.rejectionReason = reason;
  
  logAdminAction('admin_request_rejected', { requestId, username: adminReq.username, rejectedBy: req.adminUser.username, reason });
  return res.json({ ok: true, adminRequest: adminReq });
});

app.use('/api/requests', optionalAdminAuth);

app.post('/api/requests/reset', authenticateAdmin, (req, res) => {
  requests.length = 0;
  notifications.length = 0;
  return res.json({ ok: true, message: 'All requests and notifications cleared.' });
});

app.get('/api/requests', (req, res) => {
  const userId = req.query.userId;
  if (userId) {
    return res.json(requests.filter((reqItem) => reqItem.studentId === userId.toString()));
  }
  return res.json(requests);
});

app.get('/api/requests/status-summary', (req, res) => {
  const userId = req.query.userId;
  const filteredRequests = userId ? requests.filter((reqItem) => reqItem.studentId === userId.toString()) : requests;
  const summary = {
    submitted: 0,
    pending: 0,
    completed: 0,
    rejected: 0,
    total: filteredRequests.length,
    latestStatus: null
  };

  const latestRequest = filteredRequests
    .slice()
    .sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt))[0];

  if (latestRequest) {
    summary.latestStatus = latestRequest.status;
  }

  filteredRequests.forEach((reqItem) => {
    const status = (reqItem.status || '').toLowerCase();
    if (status === 'submitted') {
      summary.submitted += 1;
    } else if (status === 'verification' || status === 'processing') {
      summary.pending += 1;
    } else if (status === 'ready' || status === 'completed') {
      summary.completed += 1;
    } else if (status === 'rejected') {
      summary.rejected += 1;
    }
  });

  return res.json(summary);
});

app.get('/api/requests/:id', (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Note: In production, validate that requester is either admin or owns this request via userId/auth token
  return res.json(request);
});

app.get('/api/requests/:id/status', (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Note: In production, validate that requester is either admin or owns this request via userId/auth token
  return res.json({ id: request.id, status: request.status, updatedAt: request.updatedAt });
});

app.post('/api/requests', enforceSingleActiveRequest, (req, res) => {
  const payload = req.body || {};
  if (!payload.studentId || !(payload.studentName || payload.fullName) || !payload.type) {
    return res.status(400).json({ error: 'missing required request data' });
  }

  if (!payload.photoName || payload.photoName === 'No photo uploaded') {
    return res.status(400).json({
      error: 'photo_upload_required',
      message: 'Photo upload is required to proceed.'
    });
  }

  const record = createRequestRecord(payload);
  createRequestNotificationEvent(record, 'request.new');
  return res.status(201).json({ ok: true, request: record });
});

app.patch('/api/requests/:id/status', authenticateAdmin, (req, res) => {
  const { status, rejectionReason, details, actorRole } = req.body || {};
  const allowedStatuses = ['Submitted', 'Verification', 'Processing', 'Ready', 'Rejected'];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'missing or invalid status' });
  }

  // Enforce role-based status transitions: only admins may move requests into verification/processing/ready/rejected
  const adminOnlyStatuses = ['Verification', 'Processing', 'Ready', 'Rejected'];
  const role = (actorRole || 'student').toString().toLowerCase();
  if (adminOnlyStatuses.includes(status) && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden', message: 'Only admin users can change request status to the requested value.' });
  }

  if (role === 'admin' && !req.adminUser) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid admin token required for admin status changes.' });
  }

  // Capture who updated the status for audit and broadcast
  const updatedBy = (req.body.updatedBy || req.body.actorId || 'admin').toString();
  const request = updateRequestStatusRecord(req.params.id, status, { rejectionReason, details, updatedBy });
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Log admin action for audit trail
  if (role === 'admin') {
    logAdminAction('status_change', {
      requestId: request.id,
      studentId: request.studentId,
      status,
      updatedBy,
      details: details || request.rejectionReason || ''
    });
  }
  const eventType = status === 'Submitted' ? 'request.new' :
                    status === 'Verification' ? 'request.verification' :
                    status === 'Processing' ? 'request.processing' :
                    status === 'Ready' ? 'request.completed' :
                    status === 'Completed' ? 'request.completed' :
                    status === 'Rejected' ? 'request.rejected' :
                    'request.update';
  createRequestNotificationEvent(request, eventType, { details: details || request.rejectionReason });
  return res.json({ ok: true, request });
});

app.patch('/api/requests/:id', optionalAdminAuth, (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  const updates = req.body || {};
  // Prevent students from changing status via the general update endpoint
  if (updates.status) {
    const actorRole = (updates.actorRole || 'student').toString().toLowerCase();
    if (actorRole !== 'admin') {
      return res.status(403).json({ error: 'forbidden', message: 'Only admin users may change request status.' });
    }
    if (!req.adminUser) {
      return res.status(401).json({ error: 'unauthorized', message: 'Valid admin token required for admin status changes.' });
    }
  }
  Object.assign(request, updates);
  request.updatedAt = new Date().toISOString();
  return res.json({ ok: true, request });
});

function createNotification(data) {
  const now = new Date().toISOString();
  const notification = {
    notification_id: `NOTIF-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    user_id: (data.userId || data.user_id || 'unknown').toString(),
    title: data.title,
    message: data.message,
    status: data.status || 'unread',
    timestamp: data.timestamp || now,
    category: data.category || 'System Alerts',
    type: data.type || 'notification',
    tone: data.tone || 'gray',
    icon: data.icon || 'fa-bell',
    details: data.details || '',
    sourceId: data.sourceId || data.requestId || null
  };

  notifications.unshift(notification);
  return notification;
}

app.get('/notifications', (req, res) => {
  const userId = req.query.userId;
  let out = notifications;
  if (userId) {
    out = notifications.filter((item) => item.user_id === userId.toString());
  }
  return res.json(out);
});

app.post('/notifications', authenticateAdmin, (req, res) => {
  const { userId, title, message } = req.body || {};
  if (!userId || !title || !message) {
    return res.status(400).json({ error: 'missing userId, title, or message' });
  }

  const notification = createNotification(req.body);
  broadcast(notification);
  return res.status(201).json({ ok: true, notification });
});

app.post('/notifications/mark-all-read', (req, res) => {
  const { userId } = req.body || {};
  if (!userId) {
    return res.status(400).json({ error: 'missing userId' });
  }

  const updated = notifications.filter((item) => item.user_id === userId.toString());
  updated.forEach((item) => { item.status = 'read'; });
  return res.json({ ok: true, updatedCount: updated.length });
});

// Audit logs (admin access expected in production)
app.get('/api/audit-logs', authenticateAdmin, (req, res) => {
  return res.json(auditLogs);
});

// Live IDEAS event streaming via WebSocket
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

function broadcast(event) {
  const payload = JSON.stringify(event);
  for (const ws of clients) {
    if (ws.readyState !== ws.OPEN) continue;
    try {
      // Admin clients receive all events
      if (ws.role === 'admin' || (ws.accountType && ws.accountType === 'admin')) {
        ws.send(payload);
        continue;
      }

      // For student clients, only forward events that target their studentId
      const targetId = event.userId || event.user_id || event.studentId || event.student_id || (event.request && event.request.studentId);
      if (targetId && ws.userId && targetId.toString() === ws.userId.toString()) {
        ws.send(payload);
      }
    } catch (e) {
      console.warn('Broadcast failed for a client', e);
    }
  }
}

wss.on('connection', (ws) => {
  clients.add(ws);
  // default metadata
  ws.userId = null;
  ws.role = null;

  ws.send(JSON.stringify({
    type: 'system',
    category: 'System Alerts',
    title: 'Live activity feed connected',
    message: 'Your IDEAS notification center is now receiving real-time updates. Please identify using { type: "identify", role, userId }',
    timestamp: new Date().toISOString(),
    tone: 'info'
  }));

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data && data.type === 'identify') {
        ws.userId = data.userId ? data.userId.toString() : null;
        ws.role = data.role ? data.role.toString() : null;
        // acknowledge
        ws.send(JSON.stringify({ type: 'identified', userId: ws.userId, role: ws.role, timestamp: new Date().toISOString() }));
      }
    } catch (e) {
      // ignore non-json or unexpected messages
    }
  });

  ws.on('close', () => clients.delete(ws));
});

app.post('/events', (req, res) => {
  const event = req.body || {};
  if (!event.type || !event.title) {
    return res.status(400).json({ error: 'missing event type or title' });
  }

  const payload = {
    ...event,
    timestamp: new Date().toISOString(),
  };
  broadcast(payload);
  return res.json({ ok: true, event: payload });
});

app.post('/events/simulate', (req, res) => {
  const event = req.body.event || {
    type: 'request.new',
    category: 'Request Updates',
    title: 'New ID Request Submitted',
    message: 'A student has submitted a new ID request for processing.',
    tone: 'orange'
  };
  const payload = { ...event, timestamp: new Date().toISOString() };
  broadcast(payload);
  return res.json({ ok: true, event: payload });
});

const sampleEvents = [
  {
    type: 'request.new',
    category: 'Request Updates',
    title: 'New ID Request Submitted',
    message: 'A student has submitted a new ID request for processing in IDEAS.',
    tone: 'orange'
  },
  {
    type: 'request.review',
    category: 'Request Updates',
    title: 'Request Under Review',
    message: 'An admin is validating the submitted documents and matching them to your profile.',
    tone: 'blue'
  },
  {
    type: 'request.approved',
    category: 'Request Updates',
    title: 'Request Approved',
    message: 'Your ID request has been approved. The next step is fulfillment and dispatch.',
    tone: 'green'
  },
  {
    type: 'request.rejected',
    category: 'Request Updates',
    title: 'Request Rejected',
    message: 'The request was rejected due to missing documentation. Please resubmit the missing items.',
    tone: 'red'
  },
  {
    type: 'account.security',
    category: 'Account Actions',
    title: 'Security alert',
    message: 'A new sign-in attempt occurred from a device we do not recognize.',
    tone: 'red'
  },
  {
    type: 'system.maintenance',
    category: 'System Alerts',
    title: 'Maintenance scheduled',
    message: 'Scheduled maintenance will start Sunday at 2:00 AM. Some services may be temporarily unavailable.',
    tone: 'blue'
  }
];

let sampleIndex = 0;
setInterval(() => {
  if (clients.size > 0) {
    const event = { ...sampleEvents[sampleIndex], timestamp: new Date().toISOString() };
    broadcast(event);
    sampleIndex = (sampleIndex + 1) % sampleEvents.length;
  }
}, 18000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Presence and events server listening on http://localhost:${PORT}`));
