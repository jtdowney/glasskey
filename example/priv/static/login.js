if (checkWebAuthn()) {
  document.getElementById('passkey-btn').addEventListener('click', async () => {
    const statusEl = document.getElementById('status');
    const btn = document.getElementById('passkey-btn');

    try {
      btn.setAttribute('aria-busy', 'true');
      statusEl.textContent = 'Requesting challenge...';

      const beginRes = await fetch('/api/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      if (!beginRes.ok) {
        const err = await beginRes.json();
        throw new Error(err.error || 'Login failed');
      }

      const { session_id, options } = await beginRes.json();
      const optionsJSON = JSON.parse(options);

      statusEl.textContent = 'Select your passkey...';
      const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });

      statusEl.textContent = 'Verifying...';

      const completeRes = await fetch('/api/login/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id,
          response: JSON.stringify(response),
        }),
      });

      if (!completeRes.ok) {
        const err = await completeRes.json();
        throw new Error(err.error || 'Login failed');
      }

      window.location.href = '/welcome';

    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message;
      console.error('Login error:', err);
    } finally {
      btn.removeAttribute('aria-busy');
    }
  });
}
