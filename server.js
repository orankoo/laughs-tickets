// Base API URL
const API_BASE_URL = 'http://yourdomain.com/api';

// Fetch events from backend
async function loadEvents() {
    try {
        const response = await fetch(`${API_BASE_URL}/events`);
        const data = await response.json();
        
        if (data.status === 'success') {
            renderEvents(data.data);
        } else {
            console.error('Error loading events:', data.error);
        }
    } catch (error) {
        console.error('Error loading events:', error);
    }
}

// User registration
async function registerUser(userData) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            // Save token and user data
            localStorage.setItem('token', data.data.token);
            localStorage.setItem('user', JSON.stringify(data.data.user));
            return data;
        } else {
            throw new Error(data.error || 'Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

// User login
async function loginUser(credentials) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            // Save token and user data
            localStorage.setItem('token', data.data.token);
            localStorage.setItem('user', JSON.stringify(data.data.user));
            return data;
        } else {
            throw new Error(data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

// Create booking
async function createBooking(bookingData) {
    try {
        const token = localStorage.getItem('token');
        
        const response = await fetch(`${API_BASE_URL}/bookings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(bookingData)
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            return data;
        } else {
            throw new Error(data.error || 'Booking failed');
        }
    } catch (error) {
        console.error('Booking error:', error);
        throw error;
    }
}

// Example usage in your existing code:
document.getElementById('register-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const userData = {
        full_name: document.getElementById('register-name').value,
        email: document.getElementById('register-email').value,
        phone: document.getElementById('register-phone').value,
        password: document.getElementById('register-password').value,
        confirm_password: document.getElementById('register-confirm').value
    };
    
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/; // At least 8 characters, one letter, one number
    if (!passwordRegex.test(userData.password)) {
        alert('Password must be at least 8 characters long and include at least one letter and one number.');
        return;
    }

    const phoneRegex = /^07\d{8}$/; // Kenyan phone number format
    if (!phoneRegex.test(userData.phone)) {
        alert('Please enter a valid phone number (e.g., 0712345678).');
        return;
    }
    
    try {
        const result = await registerUser(userData);
        alert('Registration successful!');
        closeModal();
    } catch (error) {
        alert(error.message);
    }
});

// Modified bookTicket function
async function bookTicket(eventId, ticketId, quantity) {
    try {
        // Check if user is logged in
        const token = localStorage.getItem('token');
        
        if (!token) {
            openModal('login');
            return;
        }
        
        const bookingData = {
            event_id: eventId,
            ticket_id: ticketId,
            quantity: quantity
        };
        
        const result = await createBooking(bookingData);
        alert(`Booking successful! Booking ID: ${result.data.booking_id}`);
    } catch (error) {
        alert(`Booking failed: ${error.message}`);
    }
}

function trapFocus(e) {
    const modal = document.getElementById('auth-modal');
    const focusableElements = modal.querySelectorAll('input, button, [tabindex]:not([tabindex="-1"])');
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (e.key === 'Tab') {
        if (e.shiftKey) {
            if (document.activeElement === firstElement) {
                e.preventDefault();
                lastElement.focus();
            }
        } else {
            if (document.activeElement === lastElement) {
                e.preventDefault();
                firstElement.focus();
            }
        }
    } else if (e.key === 'Escape') {
        closeModal();
    }
}