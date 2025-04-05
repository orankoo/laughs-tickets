// Base API URL - Local Development
const API_BASE_URL = 'http://localhost:8000/api/v1';  // Adjust to your local server's URL

// Fetch wrapper with improved error handling
async function apiRequest(endpoint, method = 'GET', body = null, requiresAuth = false) {
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    if (requiresAuth) {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Authentication required');
        }
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method,
        headers,
        mode: 'cors', // Optional, only required if you're dealing with CORS issues in local dev
        credentials: 'include' // Optional, depending on your setup for session management
    };

    if (body) {
        config.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_BASE_URL}/${endpoint}`, config);

        if (!response.ok) {
            let errorData = {};
            try {
                errorData = await response.json();
            } catch (jsonError) {
                errorData = { message: `HTTP error! status: ${response.status}` };
            }
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error(`API Request Error [${endpoint}]:`, error);
        if (error.message.includes('Failed to fetch')) {
            throw new Error('Network error - please check your connection and CORS settings');
        }
        throw error;
    }
}

// Load events with filtering support
async function loadEvents(filters = {}) {
    try {
        const query = new URLSearchParams(filters).toString();
        const data = await apiRequest(`events?${query}`);
        renderEvents(data.data);
    } catch (error) {
        console.error('Error loading events:', error.message);
        renderEvents([]); // Fallback to empty array or cached data
    }
}
async function registerUser(userData) {
    try {
        // Input validation
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
        if (!passwordRegex.test(userData.password)) {
            throw new Error('Password must be at least 8 characters with letters and numbers');
        }

        const phoneRegex = /^07\d{8}$/;
        if (!phoneRegex.test(userData.phone)) {
            throw new Error('Please enter a valid Kenyan phone number (e.g. 0712345678)');
        }

        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });

        if (!response.ok) {
            // Handle non-OK responses
            const errorData = await response.text(); // Get response as text first
            try {
                const jsonError = JSON.parse(errorData); // Try parsing it as JSON
                throw new Error(jsonError.message || 'Registration failed');
            } catch (e) {
                throw new Error(errorData || 'An unknown error occurred');
            }
        }

        const data = await response.json(); // Only parse as JSON if OK
        // Success case
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        return data;
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

// Add event listener for form submission
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
        const result = await registerUser(userData);
        // Redirect or show success message
        openModal('login');
    } catch (error) {
        // Show error message to user
        alert(error.message);
    }
});



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

// Submit review functionality
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

// Book ticket
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


// Review form handler
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

// Focus trap for modal
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