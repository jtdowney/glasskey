function checkWebAuthn() {
  if (!window.PublicKeyCredential) {
    const main = document.querySelector('main');
    const article = document.createElement('article');
    const header = document.createElement('header');
    const h2 = document.createElement('h2');
    h2.textContent = 'WebAuthn Not Supported';
    header.appendChild(h2);
    const p = document.createElement('p');
    p.textContent = 'Your browser does not support WebAuthn. Please use a modern browser.';
    article.appendChild(header);
    article.appendChild(p);
    main.replaceChildren(article);
    return false;
  }
  return true;
}
