/**
 * script.js - Client-Side Interactive Helpers
 * Localhost Portal & SQL-Based Data Leak Detection System
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log("Localhost Secure Portal loaded successfully.");
});

/**
 * Switches between Sign In and Create Account tabs on the login page.
 * @param {'login' | 'register'} tab
 */
function switchTab(tab) {
    const tabSignIn = document.getElementById('tabSignIn');
    const tabCreate = document.getElementById('tabCreate');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    if (!tabSignIn || !tabCreate || !loginForm || !registerForm) return;

    if (tab === 'register') {
        tabCreate.classList.add('active');
        tabSignIn.classList.remove('active');
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        const regInput = document.getElementById('reg_name');
        if (regInput) regInput.focus();
    } else {
        tabSignIn.classList.add('active');
        tabCreate.classList.remove('active');
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        const userInput = document.getElementById('username');
        if (userInput) userInput.focus();
    }
}

/**
 * Toggles password visibility for the given input field.
 * @param {string} fieldId - ID of password input element
 * @param {HTMLElement} btn - The toggle button element
 */
function togglePassword(fieldId, btn) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    if (field.type === 'password') {
        field.type = 'text';
        btn.innerHTML = '🙈';
        btn.title = 'Hide password';
    } else {
        field.type = 'password';
        btn.innerHTML = '👁️';
        btn.title = 'Show password';
    }
}

/**
 * Toggles the collapsible demo credentials and test payloads drawer.
 */
function toggleDemoDrawer() {
    const content = document.getElementById('demoDrawerContent');
    const arrow = document.getElementById('demoDrawerArrow');
    if (!content) return;

    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        if (arrow) arrow.textContent = '▲';
    } else {
        content.classList.add('hidden');
        if (arrow) arrow.textContent = '▼';
    }
}

/**
 * Fills the login form with preset test credentials.
 * @param {string} username - Sample username or SQLi attack string
 * @param {string} password - Sample password
 */
function quickFill(username, password) {
    // Switch to Sign In tab if currently in register tab
    switchTab('login');

    const userField = document.getElementById('username');
    const passField = document.getElementById('password');

    if (userField && passField) {
        userField.value = username;
        passField.value = password;

        // Visual flash effect to show field was populated
        userField.classList.add('field-highlight');
        passField.classList.add('field-highlight');

        setTimeout(() => {
            userField.classList.remove('field-highlight');
            passField.classList.remove('field-highlight');
        }, 600);

        userField.focus();
    }
}

/**
 * Fills the dashboard Live Inspector textarea with a demo query or sensitive string.
 * @param {string} text - Test string (SQL query, phone number, email, or safe input)
 */
function setInspectorTest(text) {
    const textarea = document.getElementById('test_input');
    if (textarea) {
        textarea.value = text;
        textarea.focus();

        textarea.classList.add('field-highlight');
        setTimeout(() => {
            textarea.classList.remove('field-highlight');
        }, 600);

        // Smooth scroll to inspector card
        textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

/**
 * Filters the audit logs table rows on the dashboard based on the selected action.
 * @param {string} actionFilter - 'ALL' | 'ALLOWED' | 'FLAGGED' | 'BLOCKED'
 */
function filterTable(actionFilter) {
    // Update active button state
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        if (btn.innerText.toUpperCase().includes(actionFilter)) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    const rows = document.querySelectorAll('.security-table tbody .log-row');
    rows.forEach(row => {
        const rowAction = row.getAttribute('data-action') || '';
        if (actionFilter === 'ALL') {
            row.style.display = '';
        } else if (actionFilter === 'ALLOWED') {
            if (rowAction === 'ALLOWED' || rowAction === 'LOGIN SUCCESS' || rowAction === 'USER REGISTERED') {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        } else if (actionFilter === 'BLOCKED') {
            if (rowAction === 'BLOCKED' || rowAction === 'LOGIN REJECTED' || rowAction === 'LOGIN FAILED') {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        } else if (rowAction === actionFilter) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}
