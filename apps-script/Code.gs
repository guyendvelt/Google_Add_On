/**
 * Malicious Email Scorer — Gmail Add-on client (Phase 6).
 *
 * Triggered when the user opens an email. Extracts sender/subject/body/links,
 * POSTs them to the FastAPI backend (via ngrok), and renders the score +
 * verdict + reasoning in a color-coded sidebar card.
 */

// Update this if the ngrok static domain ever changes.
var BACKEND_URL = 'https://routing-recant-worry.ngrok-free.dev/api/analyze';

var MAX_LINKS = 500;              // matches schemas.MAX_LINKS
var MAX_LINK_LEN = 4096;          // matches schemas.MAX_LINK_LEN
var MAX_BODY_LEN = 200000;        // matches schemas.MAX_BODY_LEN
var MAX_SUBJECT_LEN = 2048;       // matches schemas.MAX_SUBJECT_LEN
var MAX_SENDER_LEN = 320;         // matches schemas.MAX_SENDER_LEN
var MAX_ATTACHMENTS = 50;         // matches schemas.MAX_ATTACHMENTS
var MAX_FILENAME_LEN = 255;       // matches schemas.MAX_FILENAME_LEN
var MAX_CONTENT_TYPE_LEN = 255;   // matches schemas.MAX_CONTENT_TYPE_LEN

// 5-level risk spectrum. Keys MUST match schemas.Verdict exactly.
var VERDICT_STYLE = {
  'Safe':       { color: '#188038', label: 'SAFE',        emoji: '✅' },
  'Low Risk':   { color: '#AFB42B', label: 'LOW RISK',    emoji: '🟢' },
  'Suspicious': { color: '#F9A825', label: 'SUSPICIOUS',  emoji: '⚠️' },
  'High Risk':  { color: '#EF6C00', label: 'HIGH RISK',   emoji: '🟠' },
  'Malicious':  { color: '#C62828', label: 'MALICIOUS',   emoji: '🛑' },
};

// Fallback used when the backend ever returns an unknown verdict string.
var FALLBACK_STYLE = VERDICT_STYLE.Suspicious;

// Score → verdict (mirrors main._verdict_for_score). Used only as a safety net
// if the response is malformed; normally we trust result.verdict.
function verdictFromScore_(score) {
  if (score <= 20) return 'Safe';
  if (score <= 40) return 'Low Risk';
  if (score <= 60) return 'Suspicious';
  if (score <= 80) return 'High Risk';
  return 'Malicious';
}

/**
 * Contextual trigger entry point (wired in appsscript.json).
 * Returns an array with one built Card.
 */
function onGmailMessage(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(e.gmail.messageId);

    var payload = buildPayload_(message);
    var result  = callBackend_(payload);

    return [buildResultCard_(result, payload.sender).build()];
  } catch (err) {
    console.error('onGmailMessage failed: ' + (err && err.stack ? err.stack : err));
    return [buildErrorCard_(err).build()];
  }
}

/**
 * Builds the JSON body that matches schemas.EmailAnalysisRequest exactly.
 * Backend rejects unknown fields (extra="forbid") — keep keys in sync.
 */
function buildPayload_(message) {
  var sender = truncate_(message.getFrom() || 'unknown@unknown', MAX_SENDER_LEN);
  if (!sender) sender = 'unknown@unknown';

  return {
    sender:      sender,
    subject:     truncate_(message.getSubject() || '', MAX_SUBJECT_LEN),
    body:        truncate_(message.getPlainBody() || '', MAX_BODY_LEN),
    links:       extractLinks_(message),
    attachments: extractAttachments_(message),
  };
}

/**
 * Builds the AttachmentInfo[] payload for the backend.
 *
 * For each real attachment (inline images excluded), we send:
 *   - name:         filename (truncated, lowercase preserved for fidelity)
 *   - sha256:       hex digest of the file bytes (computed client-side so
 *                   the raw file never leaves the user's Gmail account)
 *   - size:         byte length
 *   - content_type: MIME type as reported by Gmail
 *
 * Backend rejects unknown fields (extra="forbid"), so the key set is exact.
 */
function extractAttachments_(message) {
  var atts = message.getAttachments({
    includeInlineImages: false,
    includeAttachments:  true,
  });

  var out = [];
  for (var i = 0; i < atts.length && out.length < MAX_ATTACHMENTS; i++) {
    var att = atts[i];
    var name = truncate_(att.getName() || '', MAX_FILENAME_LEN);
    if (!name) continue;

    var bytes;
    try {
      bytes = att.getBytes();
    } catch (e) {
      // getBytes can fail for some Gmail attachment kinds (e.g. encrypted
      // S/MIME parts). Skip rather than aborting the whole scan.
      console.warn('Skipping attachment "' + name + '": ' + e);
      continue;
    }

    var digestBytes = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256, bytes
    );

    out.push({
      name:         name,
      sha256:       bytesToHex_(digestBytes),
      size:         bytes.length,
      content_type: truncate_(att.getContentType() || '', MAX_CONTENT_TYPE_LEN),
    });
  }
  return out;
}

/**
 * Converts Apps Script's signed-byte digest array to a lowercase hex string.
 * Utilities.computeDigest returns Java-style signed bytes (-128..127); the
 * & 0xFF mask normalizes them to the 0..255 range expected for hex encoding.
 */
function bytesToHex_(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i] & 0xFF;
    if (b < 16) hex += '0';
    hex += b.toString(16);
  }
  return hex;
}

/**
 * Collects URLs from the email. Combines:
 *   1) <a href="..."> from the HTML body — catches display/href mismatch.
 *   2) Bare http(s):// URLs from plain + HTML bodies.
 * Deduped, capped at MAX_LINKS, each truncated to MAX_LINK_LEN.
 */
function extractLinks_(message) {
  var html  = message.getBody()       || '';
  var plain = message.getPlainBody()  || '';
  var seen  = {};
  var out   = [];

  function add(url) {
    if (out.length >= MAX_LINKS) return false;
    url = url.trim();
    if (!/^https?:\/\//i.test(url)) return true;
    if (url.length > MAX_LINK_LEN) url = url.slice(0, MAX_LINK_LEN);
    if (seen[url]) return true;
    seen[url] = true;
    out.push(url);
    return true;
  }

  var hrefRe = /href\s*=\s*["']([^"']+)["']/gi;
  var m;
  while ((m = hrefRe.exec(html)) !== null) {
    if (!add(m[1])) return out;
  }

  var urlRe = /\bhttps?:\/\/[^\s<>"'`]+/gi;
  var sources = [plain, html];
  for (var i = 0; i < sources.length; i++) {
    var u;
    while ((u = urlRe.exec(sources[i])) !== null) {
      // strip trailing punctuation that's almost never part of a real URL
      var url = u[0].replace(/[)\].,;!?]+$/, '');
      if (!add(url)) return out;
    }
  }

  return out;
}

/**
 * POSTs the payload to FastAPI. Throws on non-2xx or non-JSON response.
 */
function callBackend_(payload) {
  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true,
    headers: {
      // Bypass ngrok's free-tier HTML interstitial for non-browser clients.
      'ngrok-skip-browser-warning': 'true',
    },
  };

  var response = UrlFetchApp.fetch(BACKEND_URL, options);
  var code = response.getResponseCode();
  var text = response.getContentText();

  if (code < 200 || code >= 300) {
    throw new Error('Backend HTTP ' + code + ': ' + truncate_(text, 400));
  }

  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error('Backend returned non-JSON: ' + truncate_(text, 400));
  }

  if (typeof parsed.score !== 'number' || !parsed.verdict || !parsed.reasoning) {
    throw new Error('Backend response missing required fields.');
  }
  return parsed;
}

// -------------------------- UI --------------------------

// Unicode directional embedding: forces the wrapped string to render
// left-to-right even when the user's Gmail UI is RTL (Hebrew/Arabic).
// Without this, the BiDi algorithm treats leading bullets and trailing
// periods as neutral punctuation and flips them to the wrong side —
// you get ".This email appears safe •" instead of "• This email...".
var LRE = '‪';   // LEFT-TO-RIGHT EMBEDDING
var PDF = '‬';   // POP DIRECTIONAL FORMATTING

function ltr_(s) { return LRE + s + PDF; }

function buildResultCard_(result, senderForHeader) {
  var score     = (typeof result.score === 'number') ? result.score : 0;
  var verdict   = result.verdict || verdictFromScore_(score);
  var reasoning = result.reasoning || '';
  var style     = VERDICT_STYLE[verdict] || FALLBACK_STYLE;

  var header = CardService.newCardHeader()
    .setTitle(ltr_('Email Threat Analysis'))
    .setSubtitle(ltr_('Sender: ' + truncate_(senderForHeader, 80)))
    .setImageUrl('https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png')
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  // ---------- Centerpiece: verdict + score ----------
  // Color-coded, bold, LTR-forced — first thing the user sees.
  var verdictWidget = CardService.newDecoratedText()
    .setTopLabel(ltr_('VERDICT'))
    .setText(
      ltr_(
        '<font color="' + style.color + '"><b>' +
          style.emoji + ' ' + style.label +
        '</b></font>'
      )
    )
    .setWrapText(true);

  var scoreWidget = CardService.newDecoratedText()
    .setTopLabel(ltr_('RISK SCORE'))
    .setText(
      ltr_('<font color="' + style.color + '"><b>' + score + ' / 100</b></font>')
    )
    .setWrapText(true);

  var headlineSection = CardService.newCardSection()
    .addWidget(verdictWidget)
    .addWidget(scoreWidget);

  // ---------- Analysis ----------
  // Custom bold header (the built-in setHeader is light gray and cannot
  // be re-styled). Empty paragraph below acts as a vertical spacer.
  var reasoningParts = String(reasoning).split(' | ').filter(function (p) {
    return p && p.trim().length > 0;
  });

  // Each bullet is its own LTR embedding so the period stays at the end.
  // Single regular space after the bullet character — no &nbsp; runs.
  var bulletsHtml = reasoningParts
    .map(function (p) { return ltr_('• ' + escapeHtml_(p)); })
    .join('<br><br>');

  var analysisHeader = CardService.newTextParagraph()
    .setText(ltr_('<b><font color="#3C4043">ANALYSIS</font></b>'));

  var analysisSpacer = CardService.newTextParagraph().setText(' ');

  var analysisBody = CardService.newTextParagraph().setText(bulletsHtml);

  var analysisSection = CardService.newCardSection()
    .addWidget(analysisHeader)
    .addWidget(analysisSpacer)
    .addWidget(analysisBody);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(headlineSection)
    .addSection(analysisSection);
}

function buildErrorCard_(err) {
  var header = CardService.newCardHeader()
    .setTitle(ltr_('Analysis Unavailable'))
    .setSubtitle(ltr_('Could not reach the scoring backend.'));

  var reason = String(err && err.message ? err.message : err);

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel(ltr_('Reason'))
        .setText(ltr_(escapeHtml_(truncate_(reason, 500))))
        .setWrapText(true)
    )
    .addWidget(
      // Per-line LTR embedding — same pattern as the analysis bullets, so the
      // leading "•" stays on the left even on an RTL Gmail locale.
      CardService.newTextParagraph().setText(
        ltr_('<b>Checklist:</b>') + '<br>' +
        ltr_('•  uvicorn is running on port 8000') + '<br>' +
        ltr_('•  ngrok tunnel is up at the configured BACKEND_URL') + '<br>' +
        ltr_('•  Open <font color="#1A73E8">http://127.0.0.1:4040</font> to inspect requests')
      )
    );

  return CardService.newCardBuilder().setHeader(header).addSection(section);
}

// ----------------------- Helpers -----------------------

function truncate_(s, n) {
  s = (s == null) ? '' : String(s);
  return s.length > n ? s.slice(0, n) : s;
}

function escapeHtml_(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
