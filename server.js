require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'laughs_and_tickets',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// M-Pesa Credentials
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;
const MPESA_PASSKEY = process.env.MPESA_PASSKEY;
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE;
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL || 'https://yourdomain.com/mpesa-callback';

// Helper function to execute SQL queries
async function query(sql, params) {
    const [rows] = await pool.execute(sql, params);
    return rows;
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Generate M-Pesa access token
async function getMpesaAccessToken() {
    try {
        const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
        const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: {
                Authorization: `Basic ${auth}`
            }
        });
        return response.data.access_token;
    } catch (error) {
        console.error('Error getting M-Pesa token:', error);
        throw error;
    }
}

// ========== API Endpoints ==========

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { full_name, email, phone, password } = req.body;
        
        // Validate input
        if (!full_name || !email || !phone || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        // Check if user exists
        const existingUser = await query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone]);
        if (existingUser.length > 0) {
            return res.status(400).json({ error: 'User with this email or phone already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        await query(
            'INSERT INTO users (full_name, email, phone, password) VALUES (?, ?, ?, ?)',
            [full_name, email, phone, hashedPassword]
        );
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const [user] = await query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Check password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.user_id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token,
            user: {
                id: user.user_id,
                name: user.full_name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all events
app.get('/api/events', async (req, res) => {
    try {
        const { location, date, search } = req.query;
        let sql = 'SELECT * FROM events WHERE 1=1';
        const params = [];
        
        if (location) {
            sql += ' AND location LIKE ?';
            params.push(`%${location}%`);
        }
        
        if (date) {
            sql += ' AND DATE(event_date) = ?';
            params.push(date);
        }
        
        if (search) {
            sql += ' AND (title LIKE ? OR description LIKE ? OR venue LIKE ?)';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        sql += ' ORDER BY event_date ASC';
        
        const events = await query(sql, params);
        
        // Get tickets for each event
        for (const event of events) {
            const tickets = await query('SELECT * FROM tickets WHERE event_id = ?', [event.event_id]);
            event.tickets = tickets;
        }
        
        res.json(events);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get single event
app.get('/api/events/:id', async (req, res) => {
    try {
        const eventId = req.params.id;
        const [event] = await query('SELECT * FROM events WHERE event_id = ?', [eventId]);
        
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        const tickets = await query('SELECT * FROM tickets WHERE event_id = ?', [eventId]);
        event.tickets = tickets;
        
        const reviews = await query(`
            SELECT r.*, u.full_name 
            FROM reviews r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.event_id = ?
            ORDER BY r.created_at DESC
        `, [eventId]);
        event.reviews = reviews;
        
        res.json(event);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create booking (authenticated)
app.post('/api/bookings', authenticateToken, async (req, res) => {
    try {
        const { event_id, ticket_id, quantity } = req.body;
        const user_id = req.user.userId;
        
        // Validate input
        if (!event_id || !ticket_id || !quantity || quantity <= 0) {
            return res.status(400).json({ error: 'Invalid booking details' });
        }
        
        // Check ticket availability
        const [ticket] = await query('SELECT * FROM tickets WHERE ticket_id = ? AND event_id = ?', [ticket_id, event_id]);
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        
        if (ticket.quantity_available < quantity) {
            return res.status(400).json({ error: 'Not enough tickets available' });
        }
        
        // Calculate total amount
        const total_amount = ticket.price * quantity;
        
        // Create booking
        const [result] = await query(
            'INSERT INTO bookings (user_id, event_id, ticket_id, quantity, total_amount) VALUES (?, ?, ?, ?, ?)',
            [user_id, event_id, ticket_id, quantity, total_amount]
        );
        
        // Update ticket availability
        await query(
            'UPDATE tickets SET quantity_available = quantity_available - ? WHERE ticket_id = ?',
            [quantity, ticket_id]
        );
        
        res.status(201).json({ 
            booking_id: result.insertId,
            message: 'Booking created successfully. Proceed to payment.'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// M-Pesa Payment Initiation
app.post('/api/mpesa/payment', authenticateToken, async (req, res) => {
    try {
        const { phone, amount, booking_id } = req.body;
        
        if (!phone || !amount || !booking_id) {
            return res.status(400).json({ error: 'Phone, amount and booking ID are required' });
        }
        
        // Format phone number (ensure it starts with 254)
        let formattedPhone = phone.trim();
        if (formattedPhone.startsWith('0')) {
            formattedPhone = '254' + formattedPhone.substring(1);
        } else if (formattedPhone.startsWith('+254')) {
            formattedPhone = formattedPhone.substring(1);
        }
        
        // Get access token
        const accessToken = await getMpesaAccessToken();
        
        // Current timestamp
        const timestamp = new Date().toISOString().replace(/[-:.]/g, '').slice(0, -4);
        
        // Generate password
        const password = Buffer.from(`${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`).toString('base64');
        
        // STK Push request
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            {
                BusinessShortCode: MPESA_SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: 'CustomerPayBillOnline',
                Amount: amount,
                PartyA: formattedPhone,
                PartyB: MPESA_SHORTCODE,
                PhoneNumber: formattedPhone,
                CallBackURL: MPESA_CALLBACK_URL,
                AccountReference: 'LaughsTickets',
                TransactionDesc: `Booking ${booking_id}`
            },
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );
        
        if (response.data.ResponseCode === '0') {
            // Update booking with payment request ID
            await query(
                'UPDATE bookings SET mpesa_request_id = ? WHERE booking_id = ?',
                [response.data.CheckoutRequestID, booking_id]
            );
            
            res.json({ 
                message: 'Payment request sent to your phone. Please complete the transaction.',
                checkoutRequestId: response.data.CheckoutRequestID
            });
        } else {
            throw new Error(response.data.errorMessage || 'Failed to initiate payment');
        }
    } catch (error) {
        console.error('M-Pesa payment error:', error);
        res.status(500).json({ 
            error: 'Failed to initiate payment',
            details: error.response?.data || error.message
        });
    }
});

// M-Pesa Callback (for payment confirmation)
app.post('/mpesa-callback', async (req, res) => {
    try {
        const callbackData = req.body;
        
        // Check if payment was successful
        if (callbackData.Body.stkCallback.ResultCode === 0) {
            const metadata = callbackData.Body.stkCallback.CallbackMetadata.Item;
            const amount = metadata.find(item => item.Name === 'Amount').Value;
            const receipt = metadata.find(item => item.Name === 'MpesaReceiptNumber').Value;
            const phone = metadata.find(item => item.Name === 'PhoneNumber').Value;
            const checkoutRequestId = callbackData.Body.stkCallback.CheckoutRequestID;
            
            // Update booking status
            await query(
                'UPDATE bookings SET status = "confirmed", mpesa_receipt = ? WHERE mpesa_request_id = ?',
                [receipt, checkoutRequestId]
            );
            
            console.log(`Payment confirmed for booking ${checkoutRequestId}, receipt: ${receipt}`);
        } else {
            console.error('Payment failed:', callbackData.Body.stkCallback.ResultDesc);
        }
        
        res.status(200).end();
    } catch (error) {
        console.error('Callback processing error:', error);
        res.status(500).end();
    }
});

// Get user bookings (authenticated)
app.get('/api/user/bookings', authenticateToken, async (req, res) => {
    try {
        const bookings = await query(`
            SELECT b.*, e.title AS event_title, e.event_date, e.venue, 
                   t.ticket_type, t.price, e.image_url
            FROM bookings b
            JOIN events e ON b.event_id = e.event_id
            JOIN tickets t ON b.ticket_id = t.ticket_id
            WHERE b.user_id = ?
            ORDER BY b.booking_date DESC
        `, [req.user.userId]);
        
        res.json(bookings);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create review (authenticated)
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { event_id, rating, comment } = req.body;
        const user_id = req.user.userId;
        
        // Validate input
        if (!event_id || !rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Invalid review data' });
        }
        
        // Check if user attended the event
        const [attended] = await query(`
            SELECT 1 FROM bookings 
            WHERE user_id = ? AND event_id = ? AND status = 'confirmed'
            LIMIT 1
        `, [user_id, event_id]);
        
        if (!attended) {
            return res.status(403).json({ error: 'You can only review events you attended' });
        }
        
        // Check if already reviewed
        const [existingReview] = await query(`
            SELECT 1 FROM reviews 
            WHERE user_id = ? AND event_id = ?
            LIMIT 1
        `, [user_id, event_id]);
        
        if (existingReview) {
            return res.status(400).json({ error: 'You already reviewed this event' });
        }
        
        // Create review
        await query(
            'INSERT INTO reviews (user_id, event_id, rating, comment) VALUES (?, ?, ?, ?)',
            [user_id, event_id, rating, comment]
        );
        
        res.status(201).json({ message: 'Review submitted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});