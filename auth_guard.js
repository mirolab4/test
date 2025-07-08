// auth_guard.js
// This script handles Firebase initialization, authentication state, and routing based on user roles.

// Firebase SDKs
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInAnonymously, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, doc, getDoc, collection, getDocs, setDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Global variables for Firebase config and app ID (provided by Canvas environment)
const firebaseConfig = JSON.parse(typeof __firebase_config !== 'undefined' ? __firebase_config : '{}');
export const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';

// Initialize Firebase App
export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

// Define the super admin ID number (used for initial admin setup, not direct login)
const SUPER_ADMIN_ID_NUMBER = "407176064";

// Private promise to ensure auth and permissions are checked once
let _authCheckPromise = null;

// Function to redirect to a specified URL
export function redirectTo(url) {
    // Clear any custom session storage data on logout or redirect to login page
    if (url === 'login.html' || url === 'register.html' || url === 'id_login.html') {
        sessionStorage.removeItem('customAuthUid');
        sessionStorage.removeItem('isCustomAuth');
        // Ensure Firebase Auth session is also cleared
        signOut(auth).catch(error => console.error("Error signing out during redirect:", error));
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
async function performAuthCheck() {
    const currentPage = window.location.pathname.split('/').pop();
    const publicPages = ['login.html', 'register.html']; // Pages accessible without any authentication

    // If on a public page, do nothing and let the page load
    if (publicPages.includes(currentPage)) {
        return { firebaseAuthUid: null, linkedFamilyMemberId: null, userRole: null, allowedPages: [] };
    }

    let firebaseAuthUid = null;
    let linkedFamilyMemberId = null;
    let userRole = 'viewer'; // Default role
    let allowedPages = ['dashboard.html']; // Default minimum allowed pages

    // Rely solely on Firebase Auth state for the primary UID
    await new Promise(resolve => {
        const unsubscribe = onAuthStateChanged(auth, user => {
            if (user) {
                firebaseAuthUid = user.uid;
                console.log("AuthGuard: Firebase authenticated user UID:", firebaseAuthUid);
            } else {
                // If no Firebase Auth user, redirect to login
                console.log("AuthGuard: No Firebase Auth user. Redirecting to login.");
                showAuthModal("يرجى تسجيل الدخول للوصول إلى هذه الصفحة.");
                redirectTo('login.html');
            }
            unsubscribe();
            resolve(); // Resolve the promise once auth state is determined
        });
    });

    // If after waiting for onAuthStateChanged, no firebaseAuthUid, return (redirect already handled)
    if (!firebaseAuthUid) {
        return { firebaseAuthUid: null, linkedFamilyMemberId: null, userRole: null, allowedPages: [] };
    }

    // --- Fetch user settings and role permissions ---
    try {
        // Fetch userSettings from the path: artifacts/{appId}/users/{firebaseAuthUid}/userSettings/profile
        const userSettingsRef = doc(db, `artifacts/${appId}/users/${firebaseAuthUid}/userSettings`, "profile");
        const userSettingsSnap = await getDoc(userSettingsRef);
        let userSettings = {};

        if (userSettingsSnap.exists()) {
            userSettings = userSettingsSnap.data();
            userRole = userSettings.role || 'viewer';
            linkedFamilyMemberId = userSettings.linkedFamilyMemberId || null; // Get linked family member ID
            console.log(`AuthGuard: User settings found for Firebase UID ${firebaseAuthUid}. Role: ${userRole}, Linked ID: ${linkedFamilyMemberId}`);
        } else {
            console.warn(`AuthGuard: User settings not found for Firebase UID ${firebaseAuthUid}. Creating default settings.`);
            // If userSettings don't exist, create them with default viewer role
            userRole = 'viewer';
            linkedFamilyMemberId = null; // No linked ID by default on first login

            await setDoc(userSettingsRef, {
                email: auth.currentUser.email || `anon_${firebaseAuthUid}@familyapp.com`, // Use actual email if available, else placeholder
                role: userRole,
                canLogin: true, // Default to true for email/password users
                creationDate: new Date(),
                linkedFamilyMemberId: null // No linked family member ID by default
            }, { merge: true });
            console.log(`AuthGuard: User settings created for Firebase UID ${firebaseAuthUid} with role ${userRole}.`);
            // Re-fetch to get the newly set data
            const updatedUserSettingsSnap = await getDoc(userSettingsRef);
            if (updatedUserSettingsSnap.exists()) {
                userSettings = updatedUserSettingsSnap.data();
                linkedFamilyMemberId = userSettings.linkedFamilyMemberId; // Ensure linkedFamilyMemberId is updated
            }
        }

        // Fetch all role permissions
        const rolePermissionsCollectionRef = collection(db, `artifacts/${appId}/rolePermissions`);
        const rolePermissionsSnapshot = await getDocs(rolePermissionsCollectionRef);
        const allRolesPermissions = {};
        rolePermissionsSnapshot.docs.forEach(doc => {
            allRolesPermissions[doc.id] = doc.data().allowedPages || [];
        });

        // Determine effective allowed pages: user-specific overrides role-based
        allowedPages = userSettings.allowedPages || allRolesPermissions[userRole] || ['dashboard.html', 'index.html', 'family_tree.html', 'events.html', 'profile.html', 'statistics.html', 'add_edit_person.html', 'export_data.html', 'admin_panel.html'];

        // Ensure dashboard is always accessible if authenticated
        if (!allowedPages.includes('dashboard.html')) {
            allowedPages.push('dashboard.html');
        }

        console.log(`AuthGuard: Effective allowed pages for Firebase UID ${firebaseAuthUid} (Role: ${userRole}, Linked ID: ${linkedFamilyMemberId}):`, allowedPages);

        // Check if the current page is allowed
        if (!allowedPages.includes(currentPage)) {
            console.warn(`AuthGuard: Access denied for page: ${currentPage}. Redirecting to dashboard.`);
            showAuthModal("ليس لديك الصلاحية للوصول إلى هذه الصفحة.");
            setTimeout(() => redirectTo('dashboard.html'), 1500);
            return { firebaseAuthUid: null, linkedFamilyMemberId: null, userRole: null, allowedPages: [] }; // Indicate failure to access page
        }

        console.log("AuthGuard: Authentication and authorization successful for:", currentPage);
        // Return all relevant user data
        return { firebaseAuthUid: firebaseAuthUid, linkedFamilyMemberId: linkedFamilyMemberId, userRole: userRole, allowedPages: allowedPages };

    } catch (error) {
        console.error("AuthGuard: Error during authorization check:", error);
        showAuthModal("حدث خطأ في التحقق من الصلاحيات. يرجى المحاولة مرة أخرى.");
        redirectTo('login.html'); // Redirect to standard login on error
        return { firebaseAuthUid: null, linkedFamilyMemberId: null, userRole: null, allowedPages: [] };
    }
}

// Export a function that returns a Promise for user data
export function getUserData() {
    if (!_authCheckPromise) {
        _authCheckPromise = performAuthCheck();
    }
    return _authCheckPromise;
}

// Initial run to ensure the modal is created and the first auth check happens.
// This is important for pages that load auth_guard.js directly.
document.addEventListener('DOMContentLoaded', () => {
    getUserData().then(data => {
        if (!data.firebaseAuthUid) {
            // This means a redirect already happened or auth failed.
            // No further action needed here, as the modal/redirect is handled by performAuthCheck.
        }
    }).catch(error => {
        console.error("Error in initial getUserData call:", error);
    });
});
