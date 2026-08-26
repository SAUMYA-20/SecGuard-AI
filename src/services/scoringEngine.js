/**
 * Deterministic, fully explainable scoring — kept separate from the AI
 * layer on purpose. The AI explains and remediates; it never decides
 * the number, so scores stay reproducible and auditable.
 */
function calculateDeterministicScore(headers = {}, dom = {}) {
  let score = 100;
  const deductions = [];

  if (!headers.csp) {
    score -= 20;
    deductions.push({ item: 'Content-Security-Policy', penalty: 20, reason: 'Missing Content-Security-Policy header' });
  }
  if (!headers.hsts) {
    score -= 15;
    deductions.push({ item: 'Strict-Transport-Security', penalty: 15, reason: 'Missing Strict-Transport-Security (HSTS) header' });
  }
  if (!headers.xFrame) {
    score -= 10;
    deductions.push({ item: 'X-Frame-Options', penalty: 10, reason: 'Missing X-Frame-Options (Clickjacking vulnerability)' });
  }
  if (!headers.xContentTypeOptions) {
    score -= 5;
    deductions.push({ item: 'X-Content-Type-Options', penalty: 5, reason: 'Missing X-Content-Type-Options: nosniff (MIME sniffing)' });
  }
  if (dom.vulnerableJQueryDetected) {
    score -= 20;
    deductions.push({ item: 'Vulnerable jQuery', penalty: 20, reason: 'Outdated jQuery 1.x/2.x detected (Known XSS CVEs)' });
  }
  if (dom.formActionHttp) {
    score -= 15;
    deductions.push({ item: 'Cleartext Form Action', penalty: 15, reason: 'Form action configured over insecure HTTP' });
  }
  if (dom.possibleExposedSecret) {
    score -= 10;
    deductions.push({ item: 'Exposed Secret Token', penalty: 10, reason: 'Potential exposed API key/secret in HTML source' });
  }

  score = Math.max(0, Math.min(100, score));
  return { score, deductions };
}

function gradeFromScore(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

module.exports = { calculateDeterministicScore, gradeFromScore };
