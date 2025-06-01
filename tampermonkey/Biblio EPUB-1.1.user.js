// ==UserScript==
// @name         Biblio EPUB
// @namespace    http://tampermonkey.net/
// @version      1.1
// @description  Extract ebook signed_link and key, show userId, create UI on https://biblio.app/* with detailed POST response logging
// @author       ChatGPT
// @match        https://biblio.app/reader/*
// @grant        none
// @run-at document-start
// ==/UserScript==

(function() {
  'use strict';

  let ebookData = null;
  let userId = null;

  // Create or update UI
  function createUI() {
  if (!ebookData || !userId) {
    console.log('[Ebook Extractor] Missing data:', { ebookData, userId });
    return;
  }
  console.log('[Ebook Extractor] Creating UI with:', { ebookData, userId });

  let container = document.getElementById('ebook-extractor-ui');
  if (!container) {
    container = document.createElement('div');
    container.id = 'ebook-extractor-ui';
    container.style = `
      position: fixed;
      top: 10px;
      left: 10px;
      z-index: 99999;
      padding: 12px;
      background: #fff;
      border: 2px solid #444;
      max-width: 400px;
      font-family: sans-serif;
      box-shadow: 2px 2px 8px rgba(0,0,0,0.3);
    `;
    document.body.appendChild(container);
  }

  container.innerHTML = `
    <h3 style="margin:0 0 8px;">Biblio EPUB</h3>
    <button id="copy-all-btn" style="margin-top: 10px; padding: 8px 12px; font-size: 1.2rem; cursor: pointer;">Kopiera all info</button>
  `;

  const copyAllBtn = document.getElementById('copy-all-btn');
  copyAllBtn.onclick = () => {
    const textToCopy =
      `${ebookData.signed_link};${userId};${ebookData.key}`;
    navigator.clipboard.writeText(textToCopy).then(() => {
      alert('Klistra in i decrypto.py');
    }).catch(() => {
      // fallback if clipboard API not supported
      prompt('Copy all info:', textToCopy);
    });
  };
}

  // Hook XMLHttpRequest
  (function() {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url) {
      this._method = method;
      this._url = url;
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
      this.addEventListener('load', () => {
        try {
          if (this._method === 'POST') {
            const ct = this.getResponseHeader('Content-Type') || '';
            if (ct.includes('application/json')) {
              const data = JSON.parse(this.responseText);
              console.log('[Ebook Extractor] POST XHR response for', this._url, data);

              // Detect ebook data
              if (this._url.includes('LoanManager-request_ebook_link')) {
                if (data?.result?.signed_link && data?.result?.key) {
                  ebookData = data.result;
                  createUI();
                }
              }

              // Detect user ID
              if (this._url.includes('identitytoolkit.googleapis.com/v1/accounts:lookup')) {
                if (data?.users?.length) {
                  userId = data.users[0].localId;
                  createUI();
                }
              }
            }
          }
        } catch(e) {
          console.warn('[Ebook Extractor] JSON parse error (XHR):', e);
        }
      });
      return origSend.apply(this, arguments);
    };
  })();

  // Hook fetch
  (function() {
    const origFetch = window.fetch;
    window.fetch = function(resource, init) {
      const url = (typeof resource === 'string') ? resource : resource.url;
      const method = (init && init.method) || 'GET';

      return origFetch.apply(this, arguments).then(async response => {
        try {
          if (method === 'POST') {
            const ct = response.headers.get('Content-Type') || '';
            if (ct.includes('application/json')) {
              const data = await response.clone().json();
              console.log('[Ebook Extractor] POST fetch response for', url, data);

              // Detect ebook data
              if (url.includes('LoanManager-request_ebook_link')) {
                if (data?.result?.signed_link && data?.result?.key) {
                  ebookData = data.result;
                  createUI();
                }
              }

              // Detect user ID
              if (url.includes('identitytoolkit.googleapis.com/v1/accounts:lookup')) {
                if (data?.users?.length) {
                  userId = data.users[0].localId;
                  createUI();
                }
              }
            }
          }
        } catch (e) {
          console.warn('[Ebook Extractor] JSON parse error (fetch):', e);
        }
        return response;
      });
    };
  })();

  // Initial log
  console.log('[Ebook Extractor] Script injected and hooks installed.');

})();
