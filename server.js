const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
// ============================================
// STRIPE WEBHOOKS
// ============================================

/**
 * Handle Stripe Webhooks
 * POST /api/webhook
 * 
 * IMPORTANT: This must be BEFORE express.json() middleware
 * or use express.raw() for this route specifically
 */
app.post('/api/webhook', 
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    
    let event;
    
    try {
      // Verify webhook signature
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    console.log('Webhook received:', event.type);
    
    // Handle different event types
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        console.log('Checkout completed:', session.id);
        
        // TODO: Update user to Pro in database
        const { userId, plan } = session.metadata;
        
        // In production, you would:
        // await db.users.update(userId, { 
        //   isPro: true,
        //   stripeCustomerId: session.customer,
        //   stripeSubscriptionId: session.subscription,
        //   plan: plan
        // });
        
        console.log(`User ${userId} upgraded to ${plan}`);
        break;
      }
      
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        console.log('Subscription updated:', subscription.id);
        
        // Handle tier changes, cancellations, etc.
        break;
      }
      
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        console.log('Subscription cancelled:', subscription.id);
        
        // TODO: Downgrade user to free tier
        break;
      }
      
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        console.log('Payment succeeded:', invoice.id);
        
        // Send receipt email, etc.
        break;
      }
      
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log('Payment failed:', invoice.id);
        
        // Send payment failure email
        break;
      }
      
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
    
    // Return 200 to acknowledge receipt
    res.json({ received: true });
  }
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// --- Mock Database ---

const USERS = [
    // Contractors
    { id: 'cont_1', email: 'demo@gardenmanager.com', password: 'demo123', role: 'contractor', businessName: 'GreenThumb Services', location: 'London, UK' },
    { id: 'cont_admin', email: 'admin@gardenbuddy.com', password: 'gardenbuddai', role: 'contractor', businessName: 'GardenBuddy Superuser', location: 'Global' },
    // Clients
    { id: 'client_1', email: 'client@example.com', password: 'password', role: 'client', name: 'Smith Family', contractorId: 'cont_1' }
];

let CLIENTS = [
    { id: 'client_1', name: 'Smith Family', garden: 'Rose Garden Estate', healthStatus: 'urgent', nextDue: 'Today', contractorId: 'cont_1' },
    { id: 'client_2', name: 'Jones Residence', garden: 'Lawn & Borders', healthStatus: 'healthy', nextDue: 'Mar 20', contractorId: 'cont_1' },
    { id: 'client_3', name: 'Patel Cottage', garden: 'Vegetable Patch', healthStatus: 'warning', nextDue: 'Overdue', contractorId: 'cont_1' },
    { id: 'client_4', name: 'Williams Mansion', garden: 'Formal Gardens', healthStatus: 'healthy', nextDue: 'Apr 1', contractorId: 'cont_1' }
];

let JOBS = [
    { id: 'job_1', clientName: 'Smith Family', service: 'Rose Pruning', time: '09:00', status: 'confirmed', urgent: true, contractorId: 'cont_1', date: new Date().toISOString().split('T')[0] },
    { id: 'job_2', clientName: 'Jones Residence', service: 'Lawn Treatment', time: '11:30', status: 'confirmed', urgent: false, contractorId: 'cont_1', date: new Date().toISOString().split('T')[0] },
    { id: 'job_3', clientName: 'Williams Mansion', service: 'Hedge Trimming', time: '14:00', status: 'pending', urgent: false, contractorId: 'cont_1', date: new Date().toISOString().split('T')[0] }
];

const PLANTS = {
    'tomato': { emoji: '🍅', type: 'vegetable', sun: 'Full sun (6-8 hours)', water: '1-2 inches per week', daysToHarvest: 60 },
    'basil': { emoji: '🌿', type: 'herb', sun: 'Partial to full sun', water: 'Keep soil moist', daysToHarvest: 30 },
    'lettuce': { emoji: '🥬', type: 'vegetable', sun: 'Partial sun', water: 'Keep soil moist', daysToHarvest: 45 },
    'carrot': { emoji: '🥕', type: 'vegetable', sun: 'Full sun', water: '1 inch per week', daysToHarvest: 70 },
    'pepper': { emoji: '🫑', type: 'vegetable', sun: 'Full sun', water: '1-2 inches per week', daysToHarvest: 65 },
    'cucumber': { emoji: '🥒', type: 'vegetable', sun: 'Full sun', water: '1-2 inches per week', daysToHarvest: 55 },
    'zucchini': { emoji: '🥒', type: 'vegetable', sun: 'Full sun', water: '1-2 inches per week', daysToHarvest: 50 },
    'strawberry': { emoji: '🍓', type: 'fruit', sun: 'Full sun', water: '1 inch per week', daysToHarvest: 90 },
    'rosemary': { emoji: '🌿', type: 'herb', sun: 'Full sun', water: 'Let soil dry between', daysToHarvest: 90 },
    'mint': { emoji: '🌿', type: 'herb', sun: 'Partial sun', water: 'Keep soil moist', daysToHarvest: 30 },
    'sunflower': { emoji: '🌻', type: 'flower', sun: 'Full sun', water: 'Moderate', daysToHarvest: 80 },
    'lavender': { emoji: '🪻', type: 'herb', sun: 'Full sun', water: 'Drought tolerant', daysToHarvest: 120 }
};

// --- Helper Functions ---

// Simple Mock Token Verification
const verifyToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        
        // In a real app, verify JWT here. For demo, we map token to user ID based on simple rules.
        if (bearerToken.includes('superuser')) {
            req.userId = 'cont_admin';
        } else if (bearerToken.includes('demo') || bearerToken.includes('cont')) {
            req.userId = 'cont_1';
        } else {
            req.userId = 'client_1';
        }
        next();
    } else {
        res.sendStatus(403);
    }
};

// --- Auth Routes ---

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const user = USERS.find(u => u.email === email && u.password === password);

    if (user) {
        const token = `token_${user.id}_${Date.now()}`;
        
        // Response format for Contractor App
        if (user.role === 'contractor') {
            res.json({
                success: true,
                token: token,
                user: {
                    id: user.id,
                    email: user.email,
                    businessName: user.businessName,
                    location: user.location,
                    clientCount: CLIENTS.filter(c => c.contractorId === user.id).length
                }
            });
        } 
        // Response format for Client App
        else {
            const contractor = USERS.find(u => u.id === user.contractorId);
            res.json({
                token: token,
                user: {
                    id: user.id,
                    contractorId: user.contractorId,
                    contractorName: contractor ? contractor.businessName : null
                }
            });
        }
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

app.post('/api/auth/register', (req, res) => {
    const { email, password, name } = req.body;
    
    if (USERS.find(u => u.email === email)) {
        return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    const newUser = {
        id: 'user_' + Date.now(),
        email,
        password, // In a real app, hash this!
        role: 'client',
        name: name || 'New Gardener',
        contractorId: null
    };

    USERS.push(newUser);

    const token = `token_${newUser.id}_${Date.now()}`;
    
    res.json({
        success: true,
        token: token,
        user: {
            id: newUser.id,
            contractorId: newUser.contractorId,
            contractorName: null,
            name: newUser.name
        }
    });
});

// --- Contractor Routes ---

app.get('/api/jobs/today', verifyToken, (req, res) => {
    // Filter jobs for this contractor
    const contractorJobs = JOBS.filter(j => j.contractorId === req.userId);
    res.json(contractorJobs);
});

app.get('/api/clients', verifyToken, (req, res) => {
    const myClients = CLIENTS.filter(c => c.contractorId === req.userId);
    res.json(myClients);
});

app.get('/api/stats', verifyToken, (req, res) => {
    const myClients = CLIENTS.filter(c => c.contractorId === req.userId);
    const myJobs = JOBS.filter(j => j.contractorId === req.userId);
    
    res.json({
        todayJobs: myJobs.length,
        todayRevenue: myJobs.length * 150, // Mock calculation
        totalClients: myClients.length
    });
});

app.post('/api/clients/pair', verifyToken, (req, res) => {
    const { clientId, clientName } = req.body;
    
    // Check if client already exists in our mock DB
    let client = CLIENTS.find(c => c.id === clientId);
    
    if (client) {
        // Update existing client to link to this contractor
        client.contractorId = req.userId;
    } else {
        // Create new client entry from QR scan
        client = {
            id: clientId,
            name: clientName || 'New Client',
            garden: 'Pending Setup',
            healthStatus: 'healthy',
            nextDue: 'Pending',
            contractorId: req.userId
        };
        CLIENTS.push(client);
    }
    
    res.json({ success: true, message: 'Client paired successfully' });
});

// --- Client Routes ---

app.post('/api/requests', verifyToken, (req, res) => {
    const { type, note } = req.body;
    console.log(`[API] Received request from ${req.userId}: ${type} - ${note}`);
    res.json({ success: true });
});

app.get('/api/plants', (req, res) => {
    res.json(PLANTS);
});

// ============================================
// STRIPE CHECKOUT
// ============================================

/**
 * Create Stripe Checkout Session
 * POST /api/create-checkout
 */
app.post('/api/create-checkout', async (req, res) => {
  try {
    const { priceId, userId, userEmail, plan, returnUrl } = req.body;
    
    console.log('Creating checkout session:', { priceId, userId, plan });
    
    // Validate required fields
    if (!priceId || !userEmail) {
      return res.status(400).json({
        error: 'Missing required fields',
        details: { priceId: !!priceId, userEmail: !!userEmail }
      });
    }
    
    // Create Checkout Session
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      
      // Customer info
      customer_email: userEmail,
      
      // Metadata (to identify user later)
      metadata: {
        userId: userId || 'guest',
        plan: plan || 'pro',
        appType: plan?.includes('contractor') ? 'contractor' : 'consumer'
      },
      
      // URLs
      success_url: `${process.env.APP_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: returnUrl || `${process.env.APP_URL}/`,
      
      // Allow promo codes
      allow_promotion_codes: true,
      
      // Billing info collection
      billing_address_collection: 'auto',
    });
    
    console.log('Checkout session created:', session.id);
    
    res.json({
      sessionId: session.id,
      url: session.url
    });
    
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({
      error: 'Failed to create checkout session',
      details: error.message
    });
  }
});

/**
 * Get Checkout Session Details
 * GET /api/checkout-session/:sessionId
 */
app.get('/api/checkout-session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    res.json({
      status: session.payment_status,
      customerEmail: session.customer_email,
      metadata: session.metadata
    });
    
  } catch (error) {
    console.error('Session retrieval error:', error);
    res.status(500).json({
      error: 'Failed to retrieve session',
      details: error.message
    });
  }
});

// ============================================
// STRIPE CUSTOMER PORTAL
// ============================================

/**
 * Create Customer Portal Session (manage subscription)
 * POST /api/create-portal-session
 */
app.post('/api/create-portal-session', async (req, res) => {
  try {
    const { customerId, returnUrl } = req.body;
    
    if (!customerId) {
      return res.status(400).json({ error: 'Customer ID required' });
    }
    
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl || process.env.APP_URL,
    });
    
    res.json({ url: portalSession.url });
    
  } catch (error) {
    console.error('Portal session error:', error);
    res.status(500).json({
      error: 'Failed to create portal session',
      details: error.message
    });
  }
});

// ============================================
// SUBSCRIPTION STATUS
// ============================================

/**
 * Get user's subscription status
 * GET /api/subscription-status/:userId
 */
app.get('/api/subscription-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // TODO: Get from database
    // For now, return mock data
    const user = MOCK_USERS[userId] || {
      isPro: false,
      plan: 'free',
      stripeCustomerId: null,
      stripeSubscriptionId: null
    };
    
    // If user has subscription, get details from Stripe
    if (user.stripeSubscriptionId) {
      const subscription = await stripe.subscriptions.retrieve(
        user.stripeSubscriptionId
      );
      
      return res.json({
        isPro: subscription.status === 'active',
        plan: user.plan,
        status: subscription.status,
        currentPeriodEnd: subscription.current_period_end,
        cancelAtPeriodEnd: subscription.cancel_at_period_end
      });
    }
    
    res.json({
      isPro: user.isPro || false,
      plan: user.plan || 'free',
      status: 'none'
    });
    
  } catch (error) {
    console.error('Subscription status error:', error);
    res.status(500).json({
      error: 'Failed to get subscription status',
      details: error.message
    });
  }
});

// Mock users database (replace with real DB)
const MOCK_USERS = {};

console.log('Stripe routes initialized');

app.listen(PORT, () => {
    console.log(`GardenBuddy API running at http://localhost:${PORT}`);
});