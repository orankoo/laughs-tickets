// Base API URL
const API_BASE_URL = 'https://laughs-tickets.onrender.com/api/v1';

// Improved fetch wrapper with better error handling
async function apiRequest(endpoint, method = 'GET', body = null, requiresAuth = false) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (requiresAuth) {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Authentication required');
        }
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : null
    });

    const data = await response.json();
    
    if (!response.ok) {
        throw new Error(data.message || 'Request failed');
    }

    return data;
}

// Fetch events with filtering support
async function loadEvents(filters = {}) {
    try {
        const query = new URLSearchParams(filters).toString();
        const data = await apiRequest(`events?${query}`);
        renderEvents(data.data);
    } catch (error) {
        console.error('Error loading events:', error.message);
        // Fallback to empty array or cached data if needed
        renderEvents([]);
    }
}

// User registration with enhanced validation
async function registerUser(userData) {
    try {
        // Frontend validation
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
        if (!passwordRegex.test(userData.password)) {
            throw new Error('Password must be at least 8 characters with letters and numbers');
        }

        const phoneRegex = /^07\d{8}$/;
        if (!phoneRegex.test(userData.phone)) {
            throw new Error('Please enter a valid Kenyan phone number (e.g. 0712345678)');
        }

        const data = await apiRequest('auth/register', 'POST', userData);
        
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        return data;
    } catch (error) {
        console.error('Registration error:', error.message);
        throw error;
    }
}

// User login
async function loginUser(credentials) {
    try {
        const data = await apiRequest('auth/login', 'POST', credentials);
        
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        return data;
    } catch (error) {
        console.error('Login error:', error.message);
        throw error;
    }
}

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
}

// Create booking with validation
async function createBooking(bookingData) {
    try {
        if (!bookingData.event_id || !bookingData.ticket_id || bookingData.quantity <= 0) {
            throw new Error('Invalid booking details');
        }
        
        const data = await apiRequest('bookings', 'POST', bookingData, true);
        return data;
    } catch (error) {
        console.error('Booking error:', error.message);
        throw error;
    }
}

// New review functionality
async function submitReview(reviewData) {
    try {
        if (!reviewData.event_id || reviewData.rating < 1 || reviewData.rating > 5) {
            throw new Error('Please provide a valid rating (1-5)');
        }
        
        const data = await apiRequest('reviews', 'POST', reviewData, true);
        return data;
    } catch (error) {
        console.error('Review submission error:', error.message);
        throw error;
    }
}

// Get event reviews
async function getEventReviews(eventId) {
    try {
        const data = await apiRequest(`reviews/${eventId}`);
        return data;
    } catch (error) {
        console.error('Error loading reviews:', error.message);
        throw error;
    }
}

// Updated bookTicket function
async function bookTicket(eventId, ticketId, quantity) {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            openModal('login');
            return;
        }
        
        const result = await createBooking({
            event_id: eventId,
            ticket_id: ticketId,
            quantity: quantity
        });
        
        alert(`Booking successful! Booking ID: ${result.booking_id}`);
    } catch (error) {
        alert(`Booking failed: ${error.message}`);
    }
}

// Updated registration form handler
document.getElementById('register-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const userData = {
        full_name: document.getElementById('register-name').value,
        email: document.getElementById('register-email').value,
        phone: document.getElementById('register-phone').value,
        password: document.getElementById('register-password').value,
        confirm_password: document.getElementById('register-confirm').value
    };
    
    try {
        await registerUser(userData);
        alert('Registration successful!');
        closeModal();
    } catch (error) {
        alert(error.message);
    }
});

// Example review submission handler
document.getElementById('review-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const reviewData = {
        event_id: document.getElementById('review-event-id').value,
        rating: document.getElementById('review-rating').value,
        comment: document.getElementById('review-comment').value
    };
    
    try {
        await submitReview(reviewData);
        alert('Thank you for your review!');
        closeModal();
    } catch (error) {
        alert(error.message);
    }
});

// Keep your existing trapFocus function
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