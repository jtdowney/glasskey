if (checkWebAuthn()) {
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('register-username').value.trim();
    if (!username) return;

    const statusEl = document.getElementById('status');
    const submitBtn = e.target.querySelector('button[type="submit"]');

    try {
      submitBtn.setAttribute('aria-busy', 'true');
      statusEl.textContent = 'Requesting challenge...';

      const beginRes = await fetch('/api/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });

      if (!beginRes.ok) {
        const err = await beginRes.json();
        throw new Error(err.error || 'Registration failed');
      }

      const { session_id, options } = await beginRes.json();
      const optionsJSON = JSON.parse(options);

      statusEl.textContent = 'Waiting for authenticator...';
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });

      statusEl.textContent = 'Verifying...';

      const completeRes = await fetch('/api/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id,
          response: JSON.stringify(response),
        }),
      });

      if (!completeRes.ok) {
        const err = await completeRes.json();
        throw new Error(err.error || 'Registration failed');
      }

      statusEl.textContent = 'Success! Redirecting to login...';
      setTimeout(() => window.location.href = '/login', 1500);

    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message;
      console.error('Registration error:', err);
    } finally {
      submitBtn.removeAttribute('aria-busy');
    }
  });
}
