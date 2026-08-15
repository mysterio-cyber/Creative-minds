/* =====================================================================
   FILE 2 of 5 — google-auth-client.js
   =====================================================================
   Save this file next to index.html and load it with:
     <script src="google-auth-client.js"></script>
   right before </body> (after your existing inline <script> block).

   It assumes these already exist in your page (they do, in your
   current index.html): api(), showToast(), showAuthError(),
   goStep(), setText(), updateNavForUser(), authToken, currentUser.
   ===================================================================== */

// Pull the client ID from the <body data-google-client-id="..."> attribute
// so you only ever have to edit it in one place (the HTML).
var GOOGLE_CLIENT_ID = document.body.getAttribute('data-google-client-id') || '';

var _googleInitialized = false;

function _ensureGoogleInitialized() {
  if (_googleInitialized) return true;
  if (typeof google === 'undefined' || !google.accounts) return false;
  if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.indexOf('YOUR_GOOGLE_CLIENT_ID') === 0) {
    console.warn('Google Client ID is not set. Update data-google-client-id on <body>.');
  }
  google.accounts.id.initialize({
    client_id: GOOGLE_CLIENT_ID,
    callback: handleGoogleCredential,
    auto_select: false
  });
  _googleInitialized = true;
  return true;
}

// Called when the "Continue with Google" button is clicked
function startGoogleLogin() {
  if (typeof google === 'undefined' || !google.accounts) {
    showToast('Google sign-in is still loading — try again in a second.', 'error');
    return;
  }
  _ensureGoogleInitialized();

  // Try Google's One Tap prompt first
  google.accounts.id.prompt(function (notification) {
    if (notification.isNotDisplayed && notification.isNotDisplayed()) {
      _renderGoogleFallbackButton();
    } else if (notification.isSkippedMoment && notification.isSkippedMoment()) {
      _renderGoogleFallbackButton();
    }
  });
}

// Fallback: if One Tap can't show (blocked, already dismissed, etc.),
// render Google's own hidden button and auto-click it — this always works.
function _renderGoogleFallbackButton() {
  var holder = document.getElementById('googleFallbackHolder');
  if (!holder) {
    holder = document.createElement('div');
    holder.id = 'googleFallbackHolder';
    holder.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
    document.body.appendChild(holder);
  }
  holder.innerHTML = '';
  google.accounts.id.renderButton(holder, {
    theme: 'outline',
    size: 'large',
    type: 'standard'
  });
  setTimeout(function () {
    var realBtn = holder.querySelector('div[role="button"]');
    if (realBtn) {
      realBtn.click();
    } else {
      showToast('Could not open Google sign-in. Please allow pop-ups and try again.', 'error');
    }
  }, 50);
}

// Called automatically by Google once the person picks an account.
// response.credential is a signed JWT — verify it server-side, never trust it as-is on the client.
async function handleGoogleCredential(response) {
  var btn = document.getElementById('googleBtn');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; }

  try {
    var res = await api('POST', '/auth/google', { credential: response.credential });

    authToken = res.token;
    currentUser = res.user;
    localStorage.setItem('cm_token', authToken);
    localStorage.setItem('cm_user', JSON.stringify(currentUser));

    setText('successTitle', 'Welcome, ' + currentUser.name + '!');
    setText('successSub', 'You are signed in with Google.');
    goStep(4);
    updateNavForUser();
  } catch (e) {
    showAuthError(e.message || 'Google sign-in failed. Please try again.');
  }

  if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
}

// Pre-initialize as soon as the Google script is ready, so the first
// click of the button feels instant instead of waiting on init.
window.addEventListener('load', function () {
  var tries = 0;
  var poll = setInterval(function () {
    tries++;
    if (_ensureGoogleInitialized() || tries > 40) clearInterval(poll);
  }, 250);
});
