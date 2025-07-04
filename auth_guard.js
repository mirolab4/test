// auth_guard.js
// This script handles Firebase initialization, authentication state, and routing based on user roles.

// Firebase SDKs
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInAnonymously, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, doc, getDoc, collection, getDocs } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Global variables for Firebase config and app ID (provided by Canvas environment)
const firebaseConfig = JSON.parse(typeof __firebase_config !== 'undefined' ? __firebase_config : '{}');
export const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';

// Initialize Firebase App
export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

// Global variable for initial auth token (provided by Canvas environment)
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// Function to redirect to a specified URL
export function redirectTo(url) {
    // Clear custom session storage on logout or redirect to login page
    if (url === 'id_login.html' || url === 'login.html') {
        sessionStorage.removeItem('customUserId');
        sessionStorage.removeItem('isCustomAuth');
    }
    window.location.href = url;
}

// Function to show a simple modal message (for auth_guard internal use)
function showAuthModal(message) {
    const modal = document.getElementById('authGuardModal');
    const modalMessage = document.getElementById('authGuardModalMessage');
    const closeBtn = document.getElementById('authGuardModalCloseBtn');

    if (!modal || !modalMessage || !closeBtn) {
        console.error("Auth Guard Modal elements not found. Message:", message);
        alert(message); // Fallback to alert if modal not present
        return;
    }

    modalMessage.textContent = message;
    modal.style.display = 'flex'; // Use flex to center
    closeBtn.onclick = () => {
        modal.style.display = 'none';
    };
    // Close modal if user clicks outside of it
    window.onclick = (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    };
}

// Function to create and append the auth guard modal to the body
function createAuthGuardModal() {
    if (document.getElementById('authGuardModal')) return; // Avoid re-creating

    const modalHtml = `
        <div id="authGuardModal" style="
            display: none;
            position: fixed;
            z-index: 9999; /* High z-index */
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.6);
            justify-content: center;
            align-items: center;
            font-family: 'Inter', sans-serif;
            direction: rtl;
            text-align: right;
        ">
            <div style="
                background-color: #fefefe;
                margin: auto;
                padding: 2rem;
                border-radius: 1rem;
                box-shadow: 0 5px 15px rgba(0,0,0,0.3);
                width: 90%;
                max-width: 400px;
                position: relative;
            ">
                <span id="authGuardModalCloseBtn" style="
                    color: #aaa;
                    float: left; /* Align to left for RTL */
                    font-size: 28px;
                    font-weight: bold;
                    cursor: pointer;
                    position: absolute;
                    top: 10px;
                    left: 15px;
                ">&times;</span>
                <p id="authGuardModalMessage" style="
                    font-size: 1.125rem; /* text-lg */
                    font-weight: 600; /* font-semibold */
                    color: #374151; /* gray-800 */
                    margin-bottom: 1rem;
                    text-align: center;
                    padding-top: 1rem; /* Space for close button */
                "></p>
                <button onclick="document.getElementById('authGuardModal').style.display='none';" style="
                    background-color: #4f46e5; /* Indigo */
                    color: white;
                    padding: 0.75rem 1.5rem;
                    border-radius: 0.75rem;
                    transition: background-color 0.2s;
                    cursor: pointer;
                    border: none;
                ">حسناً</button>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

// Ensure the modal is created when the DOM is ready
document.addEventListener('DOMContentLoaded', createAuthGuardModal);


// Main authentication and authorization logic
async function checkAuthAndPermissions() {
    const currentPage = window.location.pathname.split('/').pop();
    const publicPages = ['id_login.html', 'login.html']; // Pages accessible without any authentication

    // If on a public page, do nothing and let the page load
    if (publicPages.includes(currentPage)) {
        return;
    }

    let currentUserId = null;
    let isAuthenticated = false;

    // --- Custom ID-based Authentication Check ---
    const customUserId = sessionStorage.getItem('customUserId');
    const isCustomAuth = sessionStorage.getItem('isCustomAuth') === 'true';

    if (isCustomAuth && customUserId) {
        currentUserId = customUserId;
        isAuthenticated = true;
        console.log("Custom authenticated user ID:", currentUserId);
    } else {
        // --- Firebase Auth (Email/Password or Anonymous) Check ---
        // If not custom authenticated, wait for Firebase Auth state
        // This is important for initial anonymous sign-in for Firestore access if custom auth is not active
        await new Promise(resolve => {
            const unsubscribe = onAuthStateChanged(auth, user => {
                if (user) {
                    // If Firebase Auth user exists, use their UID
                    currentUserId = user.uid;
                    isAuthenticated = true;
                    console.log("Firebase authenticated user ID:", currentUserId);
                } else {
                    // If no Firebase Auth user, and not custom auth, ensure anonymous sign-in for Firestore rules
                    signInAnonymously(auth).then(anonUserCredential => {
                        currentUserId = anonUserCredential.user.uid;
                        isAuthenticated = true; // Consider anonymous as authenticated for Firestore access
                        console.log("Signed in anonymously for Firestore access:", currentUserId);
                    }).catch(error => {
                        console.error("Error signing in anonymously:", error);
                        showAuthModal("حدث خطأ في المصادقة. يرجى المحاولة مرة أخرى.");
                        redirectTo('id_login.html'); // Redirect to login on critical auth error
                    }).finally(resolve);
                }
                unsubscribe(); // Unsubscribe after initial check
            });
        });
    }

    // If still not authenticated (e.g., anonymous sign-in failed or no custom ID), redirect to login
    if (!isAuthenticated || !currentUserId) {
        console.log("Not authenticated. Redirecting to login.");
        showAuthModal("يرجى تسجيل الدخول للوصول إلى هذه الصفحة.");
        setTimeout(() => redirectTo('id_login.html'), 1500);
        return;
    }

    // Now currentUserId is set (either custom or Firebase Auth UID)
    // Fetch user settings to get role and allowed pages
    let userRole = 'viewer'; // Default role
    let allowedPages = ['dashboard.html']; // Default minimum allowed pages

    try {
        // Try to get user settings using the effective currentUserId
        const userSettingsRef = doc(db, `artifacts/${appId}/userSettings`, currentUserId);
        const userSettingsSnap = await getDoc(userSettingsRef);
        let userSettings = {};

        if (userSettingsSnap.exists()) {
            userSettings = userSettingsSnap.data();
            userRole = userSettings.role || 'viewer';
            console.log(`User settings found for ${currentUserId}. Role: ${userRole}`);
        } else {
            console.warn(`User settings not found for ${currentUserId}. Defaulting to viewer role.`);
            // If settings don't exist, create them for the current user (especially for super admin's first login)
            userRole = 'viewer'; // Default to viewer initially
            if (sessionStorage.getItem('customUserId') === '407176064') { // Check if it's the super admin ID
                userRole = 'admin';
                console.log("Super admin detected, setting role to admin.");
            }
            await setDoc(userSettingsRef, {
                email: userSettings.email || `user_${currentUserId}@familyapp.com`, // Placeholder email
                role: userRole,
                creationDate: new Date(),
                // canLogin will be true for super admin, and managed by admin for others
                canLogin: (sessionStorage.getItem('customUserId') === '407176064') ? true : false // Super admin can always login
            }, { merge: true });
            console.log(`User settings created for ${currentUserId} with role ${userRole}.`);
        }

        // Fetch all role permissions
        const rolePermissionsCollectionRef = collection(db, `artifacts/${appId}/rolePermissions`);
        const rolePermissionsSnapshot = await getDocs(rolePermissionsCollectionRef);
        const allRolesPermissions = {};
        rolePermissionsSnapshot.docs.forEach(doc => {
            allRolesPermissions[doc.id] = doc.data().allowedPages || [];
        });

        // Determine effective allowed pages: user-specific overrides role-based
        // If userSettings.allowedPages exists, use it. Otherwise, use role-based.
        // Fallback to a basic set if neither is defined.
        allowedPages = userSettings.allowedPages || allRolesPermissions[userRole] || ['dashboard.html', 'index.html', 'family_tree.html', 'events.html', 'profile.html', 'statistics.html', 'add_edit_person.html', 'export_data.html', 'admin_panel.html'];

        // Ensure dashboard is always accessible if authenticated
        if (!allowedPages.includes('dashboard.html')) {
            allowedPages.push('dashboard.html');
        }

        console.log(`Effective allowed pages for ${currentUserId} (Role: ${userRole}):`, allowedPages);

        // Check if the current page is allowed
        if (!allowedPages.includes(currentPage)) {
            console.warn(`Access denied for page: ${currentPage}. Redirecting to dashboard.`);
            showAuthModal("ليس لديك الصلاحية للوصول إلى هذه الصفحة.");
            setTimeout(() => redirectTo('dashboard.html'), 1500);
            return;
        }

        // If authenticated and authorized, proceed.
        // The page's own script will then use the exported 'auth', 'db', 'appId'
        // and fetch the actual user role and allowed pages from Firestore
        // to update its UI elements (navigation, action buttons).
        console.log("Authentication and authorization successful for:", currentPage);

    } catch (error) {
        console.error("Error during authorization check:", error);
        showAuthModal("حدث خطأ في التحقق من الصلاحيات. يرجى المحاولة مرة أخرى.");
        redirectTo('id_login.html');
    }
}

// Run the auth check when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', checkAuthAndPermissions);

// Export auth and db for use in other scripts
// This ensures other pages use the same Firebase instances
// and are aware of the authentication state managed here.
