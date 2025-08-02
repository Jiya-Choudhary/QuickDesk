document.addEventListener('DOMContentLoaded', () => {
    // Helper function to validate email format
    const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

    // Helper function to validate password strength (min 6 characters)
    const isStrongPassword = (password) => password.length >= 6;

    // Register Form Validation
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', (e) => {
            e.preventDefault();

            const username = document.getElementById('register-username').value.trim();
            const email = document.getElementById('register-email').value.trim();
            const password = document.getElementById('register-password').value;
            const confirmPassword = document.getElementById('register-confirm-password').value;

            if (!username || !email || !password || !confirmPassword) {
                alert('Please fill in all fields');
                return;
            }

            if (!isValidEmail(email)) {
                alert('Please enter a valid email address');
                return;
            }

            if (!isStrongPassword(password)) {
                alert('Password must be at least 6 characters long');
                return;
            }

            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }

            // Submit form via AJAX
            fetch('/register', {
                method: 'POST',
                body: new FormData(registerForm),
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/login';
                } else {
                    alert(data.message || 'Registration failed');
                }
            })
            .catch(error => {
                console.error(error);
                alert('An unexpected error occurred. Please try again.');
            });
        });
    }

    // Login Form Validation
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();

            const username = document.getElementById('login-username').value.trim();
            const password = document.getElementById('login-password').value;

            if (!username || !password) {
                alert('Please fill in all fields');
                return;
            }

            // Submit form via AJAX
            fetch('/login', {
                method: 'POST',
                body: new FormData(loginForm),
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/dashboard';
                } else {
                    alert(data.message || 'Login failed');
                }
            })
            .catch(error => {
                console.error(error);
                alert('An unexpected error occurred. Please try again.');
            });
        });
    }
});