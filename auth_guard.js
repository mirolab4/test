// auth_guard.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, doc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Firebase configuration (ensure this matches your project's config)
const firebaseConfig = {
    apiKey: "AIzaSyBOXGJek0FHS1VqXhkgORMq-VrPoN1db3w",
    authDomain: "family-9b0b8.firebaseapp.com",
    databaseURL: "https://family-9b0b8-default-rtdb.firebaseio.com",
    projectId: "family-9b0b8",
    storageBucket: "family-9b0b8.firebasestorage.app",
    messagingSenderId: "409089079475",
    appId: "1:409089079475:web:93f8be81e247ecfe2758c6",
    measurementId: "G-X5LDQB1WC9"
};

// Initialize Firebase if not already initialized
let app;
try {
    app = initializeApp(firebaseConfig);
} catch (error) {
    // If app is already initialized, reuse it
    if (!firebase.apps.length) {
        console.error("Firebase initialization error:", error);
    }
    app = firebase.app(); // Get the default app if already initialized
}

const auth = getAuth(app);
const db = getFirestore(app);

// Get app ID from environment or use a default
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';

// Define page access rules and required roles/permissions
const pageAccessRules = {
    'dashboard.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'index.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'family_tree.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'events.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'profile.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'add_edit_person.html': { roles: ['admin', 'editor'], authRequired: true }, // Only admin/editor can add/edit
    'export_data.html': { roles: ['admin', 'editor'], authRequired: true }, // Only admin/editor can export
    'statistics.html': { roles: ['admin', 'editor', 'viewer'], authRequired: true },
    'admin_panel.html': { roles: ['admin'], authRequired: true }, // Only admin can access admin panel
    'login.html': { roles: [], authRequired: false }, // No auth required, redirect if logged in
    'access_denied.html': { roles: [], authRequired: false }, // No auth required
    // Add other pages as needed
};

// Function to get current page name
function getCurrentPageName() {
    const path = window.location.pathname;
    return path.substring(path.lastIndexOf('/') + 1);
}

// Function to redirect
function redirectTo(page) {
    if (window.location.pathname.endsWith(page)) {
        // Already on the target page, prevent infinite redirects
        return;
    }
    window.location.href = page;
}

// Main authentication guard function
async function authGuard() {
    const currentPage = getCurrentPageName();
    const rule = pageAccessRules[currentPage];

    // If no rule is defined, deny access by default (or redirect to login)
    if (!rule) {
        console.warn(`No access rule defined for ${currentPage}. Redirecting to access denied.`);
        redirectTo('access_denied.html');
        return;
    }

    onAuthStateChanged(auth, async (user) => {
        if (user) {
            // User is signed in
            const userSettingsRef = doc(db, `artifacts/${appId}/userSettings`, user.uid);
            const userSettingsSnap = await getDoc(userSettingsRef);

            let userRole = 'viewer'; // Default role if not found
            let allowedPages = [];
            let deviceRestrictionEnabled = false;
            let lastLoginDeviceId = null;

            if (userSettingsSnap.exists()) {
                const settings = userSettingsSnap.data();
                userRole = settings.role || 'viewer';
                allowedPages = settings.allowedPages || [];
                deviceRestrictionEnabled = settings.restrictToDeviceId || false;
                lastLoginDeviceId = settings.lastLoginDeviceId || null;
                console.log(`User ${user.uid} authenticated. Role: ${userRole}, Device Restriction: ${deviceRestrictionEnabled}`);
            } else {
                // If userSettings not found, it means this user was created directly in Firebase Auth
                // without roles. Assign a default 'viewer' role and create the settings document.
                await setDoc(userSettingsRef, {
                    email: user.email,
                    role: 'viewer',
                    allowedPages: ['dashboard.html', 'index.html', 'family_tree.html', 'events.html', 'profile.html', 'statistics.html'],
                    lastLoginDeviceId: localStorage.getItem('deviceId') || null,
                    lastLoginTime: new Date()
                }, { merge: true });
                userRole = 'viewer';
                allowedPages = ['dashboard.html', 'index.html', 'family_tree.html', 'events.html', 'profile.html', 'statistics.html'];
                console.warn(`User settings not found for ${user.uid}. Created default settings.`);
            }

            // Check device restriction (only if enabled and a lastLoginDeviceId exists)
            if (deviceRestrictionEnabled && lastLoginDeviceId) {
                const currentDeviceId = localStorage.getItem('deviceId');
                if (!currentDeviceId || currentDeviceId !== lastLoginDeviceId) {
                    console.warn(`Device restriction active. Current device ID (${currentDeviceId}) does not match last login device ID (${lastLoginDeviceId}).`);
                    signOut(auth); // Sign out the user
                    showModal("تم تسجيل دخولك من جهاز غير مصرح به. يرجى تسجيل الدخول من الجهاز الأصلي أو التواصل مع المدير.", () => {
                        redirectTo('login.html');
                    });
                    return; // Stop further execution
                }
            }

            // If on login page and already logged in, redirect to dashboard
            if (currentPage === 'login.html') {
                redirectTo('dashboard.html');
                return;
            }

            // Check if user's role is allowed for this page
            const isRoleAllowed = rule.roles.includes(userRole);

            // Check if page is in allowedPages list (if specified)
            const isPageExplicitlyAllowed = allowedPages.includes(currentPage);

            if (!isRoleAllowed || !isPageExplicitlyAllowed) {
                console.warn(`Access denied for ${user.uid} (Role: ${userRole}) to ${currentPage}. Required roles: ${rule.roles.join(', ')}. Allowed pages: ${allowedPages.join(', ')}`);
                redirectTo('access_denied.html');
                return;
            }

            // If all checks pass, allow access.
            console.log(`Access granted for ${user.uid} (Role: ${userRole}) to ${currentPage}.`);

        } else {
            // User is not signed in
            if (rule.authRequired) {
                console.log(`User not authenticated. Redirecting to login from ${currentPage}.`);
                redirectTo('login.html');
            } else {
                // Page does not require authentication (e.g., login, access_denied)
                console.log(`Access allowed for unauthenticated user to ${currentPage}.`);
            }
        }
    });
}

// Function to show a modal message (replicated here for auth_guard to be self-contained)
function showModal(message, callback = () => {}) {
    const modal = document.createElement('div');
    modal.id = 'authGuardModal';
    modal.classList.add('modal');
    modal.innerHTML = `
        <div class="modal-content">
            <p class="text-lg font-semibold text-gray-800 mb-4">${message}</p>
            <button id="authGuardModalConfirmBtn" class="btn-primary">حسناً</button>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';

    document.getElementById('authGuardModalConfirmBtn').onclick = () => {
        modal.style.display = 'none';
        document.body.removeChild(modal);
        callback();
    };

    // Add basic modal styling (should match your app's modal styles)
    const style = document.createElement('style');
    style.innerHTML = `
        .modal {
            display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); justify-content: center; align-items: center;
        }
        .modal-content {
            background-color: #fefefe; margin: auto; padding: 2rem; border-radius: 1rem; box-shadow: 0 5px 15px rgba(0,0,0,0.3); width: 90%; max-width: 500px; text-align: center;
        }
        .btn-primary {
            background-color: #4f46e5; color: white; padding: 0.75rem 1.5rem; border-radius: 0.75rem; transition: background-color 0.2s; font-weight: 600;
        }
        .btn-primary:hover {
            background-color: #4338ca;
        }
    `;
    document.head.appendChild(style);
}


// Run the auth guard when the script is loaded
authGuard();

// Optionally export functions if needed by other modules
export { auth, db, appId, redirectTo, showModal };
