// CyberShield AI - Client-side Heuristic Analysis Engine (Fallback & Local Execution)

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "is.gd",
  "buff.ly", "adf.ly", "cutt.ly", "shorturl.at", "v.gd", "qr.ae", "tr.ee"
]);

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "banking", "secure", "update", "account", "free",
  "bonus", "claim", "kyc", "support", "wallet", "payroll", "credential",
  "signin", "auth", "confirm", "security", "customer-service", "helpdesk",
  "password", "verify-account", "bank-update", "refund", "prize", "gift"
];

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "club", "work", "click", "gq", "cf", "tk", "ml", "ru",
  "su", "cam", "zip", "mov", "fit", "online", "site", "vip", "icu", "biz"
]);

export function analyzeUrlLocal(urlInput) {
  const urlClean = (urlInput || "").trim();
  if (!urlClean) {
    return {
      error: "URL cannot be empty.",
      url: "",
      risk_score: 0,
      risk_level: "SAFE",
      threat_type: "None",
      indicators: [],
      explanation: "No input provided.",
      recommendation: "Please enter a valid web link."
    };
  }

  let domain = "";
  let fullPath = "";
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(urlClean);
    const parseTarget = hasScheme ? urlClean : "http://" + urlClean;
    const parsed = new URL(parseTarget);
    domain = parsed.hostname.toLowerCase();
    fullPath = (parsed.pathname + parsed.search).toLowerCase();
  } catch (e) {
    domain = urlClean.split('/')[0].split(':')[0].toLowerCase();
    fullPath = urlClean.toLowerCase();
  }

  const indicators = [];
  let totalScore = 0;

  // 1. Missing HTTPS
  if (!urlClean.toLowerCase().startsWith("https://")) {
    const scoreAdd = 15;
    totalScore += scoreAdd;
    indicators.append ? indicators.append() : indicators.push({
      code: "NO_HTTPS",
      title: "Unencrypted HTTP Connection",
      points: scoreAdd,
      category: "Protocol Security",
      description: "The link does not use HTTPS. Data transmitted over HTTP is unencrypted and susceptible to interception."
    });
  }

  // 2. IP Address in Hostname
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(domain)) {
    const scoreAdd = 25;
    totalScore += scoreAdd;
    indicators.push({
      code: "IP_HOSTNAME",
      title: "Raw IP Hostname Used",
      points: scoreAdd,
      category: "Domain Identity",
      description: "The URL connects directly to an IP address instead of a recognized domain name, masking host ownership."
    });
  }

  // 3. URL Shortener
  if (URL_SHORTENERS.has(domain)) {
    const scoreAdd = 20;
    totalScore += scoreAdd;
    indicators.push({
      code: "URL_SHORTENER",
      title: "Shortened / Masked URL",
      points: scoreAdd,
      category: "Redirection",
      description: `Domain '${domain}' is a shortener service designed to conceal destination links.`
    });
  }

  // 4. Phishing Keywords
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => domain.includes(kw) || fullPath.includes(kw));
  if (foundKeywords.length > 0) {
    const scoreAdd = 15;
    totalScore += scoreAdd;
    indicators.push({
      code: "SUSPICIOUS_KEYWORDS",
      title: "Sensitive Keywords Found",
      points: scoreAdd,
      category: "Content Pattern",
      description: `Contains high-risk security keywords: ${foundKeywords.slice(0, 3).join(", ")}.`
    });
  }

  // 5. Excessive Subdomains
  const dotCount = (domain.match(/\./g) || []).length;
  if (dotCount > 3 && !ipPattern.test(domain)) {
    const scoreAdd = 10;
    totalScore += scoreAdd;
    indicators.push({
      code: "EXCESSIVE_SUBDOMAINS",
      title: "Excessive Subdomains",
      points: scoreAdd,
      category: "Domain Identity",
      description: `Domain includes ${dotCount} subdomains, which can be an obfuscation tactic (e.g. login.bank.com.hacker.com).`
    });
  }

  // 6. Suspicious Formatting
  const suspChars = [];
  if (urlClean.includes("@")) suspChars.push("Auth symbol '@'");
  if ((domain.match(/-/g) || []).length >= 3) suspChars.push("Hyphen overloading");
  if (fullPath.includes("//")) suspChars.push("Multiple slashes in path");
  if (suspChars.length > 0) {
    const scoreAdd = 10;
    totalScore += scoreAdd;
    indicators.push({
      code: "SUSPICIOUS_CHARS",
      title: "Obfuscated / Suspicious Formatting",
      points: scoreAdd,
      category: "URL Structure",
      description: `Detected unusual URL structure: ${suspChars.join(", ")}.`
    });
  }

  // 7. Unusual TLD
  const parts = domain.split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    const scoreAdd = 15;
    totalScore += scoreAdd;
    indicators.push({
      code: "SUSPICIOUS_TLD",
      title: `High-Risk Top-Level Domain (.${tld})`,
      points: scoreAdd,
      category: "TLD Reputation",
      description: `The TLD '.${tld}' is frequently associated with low-cost disposable malicious sites.`
    });
  }

  // 8. URL Length
  if (urlClean.length > 75) {
    const scoreAdd = 10;
    totalScore += scoreAdd;
    indicators.push({
      code: "EXCESSIVE_LENGTH",
      title: "Unusually Long URL",
      points: scoreAdd,
      category: "URL Structure",
      description: `URL contains ${urlClean.length} characters. Extended URLs often hide malicious payloads.`
    });
  }

  const finalScore = Math.min(totalScore, 100);

  let riskLevel = "SAFE";
  if (finalScore >= 85) riskLevel = "CRITICAL";
  else if (finalScore >= 65) riskLevel = "HIGH";
  else if (finalScore >= 40) riskLevel = "MEDIUM";
  else if (finalScore >= 20) riskLevel = "LOW";

  let threatType = "Clean / Low Risk URL";
  const codes = indicators.map(i => i.code);
  if (codes.includes("IP_HOSTNAME") && codes.includes("SUSPICIOUS_KEYWORDS")) {
    threatType = "Credential Harvesting via IP Host";
  } else if (codes.includes("SUSPICIOUS_KEYWORDS") && (codes.includes("SUSPICIOUS_CHARS") || codes.includes("EXCESSIVE_SUBDOMAINS"))) {
    threatType = "Phishing / Brand Spoofing";
  } else if (codes.includes("URL_SHORTENER")) {
    threatType = "Masked Shortened URL Redirect";
  } else if (finalScore >= 40) {
    threatType = "Suspicious Link Pattern";
  }

  let explanation = "No significant threat indicators were detected. The URL follows standard web safety conventions.";
  let recommendation = "The link appears safe based on heuristic checks. Standard caution recommended.";

  if (riskLevel === "CRITICAL" || riskLevel === "HIGH") {
    explanation = `CyberShield AI detected multiple high-risk indicators resulting in a risk score of ${finalScore}/100. This URL closely mimics malicious credential harvesting patterns.`;
    recommendation = "DO NOT open this link or enter passwords/cards. Verify through trusted official channels.";
  } else if (riskLevel === "MEDIUM") {
    explanation = `The link exhibits moderate risk characteristics (${finalScore}/100). Attributes such as HTTP protocol or keyword patterns suggest caution.`;
    recommendation = "Proceed with caution. Inspect the domain carefully before providing personal details.";
  } else if (riskLevel === "LOW") {
    explanation = `Minor risk signatures detected (${finalScore}/100). The link is mostly safe, but stay aware.`;
    recommendation = "Verify the sender and double-check destination domain.";
  }

  return {
    url: urlClean,
    risk_score: finalScore,
    risk_level: riskLevel,
    threat_type: threatType,
    indicators,
    explanation,
    recommendation,
    analysis_type: "Local Heuristic Engine (JS Fallback)"
  };
}

// Multilingual Message Analysis Rules (EN, HI, MR)
const MESSAGE_RULES = {
  URGENCY: {
    title: "Urgency & Time Pressure",
    points: 15,
    category: "Social Engineering",
    keywords: ["urgent", "immediately", "right now", "within 24 hours", "action required", "hurry", "expire", "limited time", "तुरंत", "अतिआवश्यक", "अभी", "जल्दी", "तातडीने", "त्वरित", "लगेच", "मुदतीत"],
    desc: "Uses artificial time pressure to induce panic and prompt impulsive actions."
  },
  FEAR_SUSPENSION: {
    title: "Threat & Account Suspension Warning",
    points: 20,
    category: "Social Engineering",
    keywords: ["suspended", "blocked", "closed", "terminated", "legal action", "police", "deactivated", "penalty", "बंद", "निलंबित", "कार्रवाई", "अवरुद्ध", "ब्लॉक", "गोठवले", "अटकाव"],
    desc: "Threatens account closure or punitive consequences to force user response."
  },
  REWARD_PRIZE: {
    title: "Unrealistic Reward / Prize Offer",
    points: 18,
    category: "Baiting",
    keywords: ["won", "prize", "lottery", "cashback", "gift card", "congratulations", "free bonus", "reward", "claimed", "जीत", "पुरस्कार", "इनाम", "लॉटरी", "बोनस", "बधाई", "जिंकले", "बक्षीस", "अभिनंदन"],
    desc: "Offers unverified monetary claims or free gifts to trick victims into clicking."
  },
  SENSITIVE_INFO: {
    title: "Request for Sensitive Credentials",
    points: 25,
    category: "Credential Theft",
    keywords: ["otp", "password", "pin", "cvv", "card number", "bank account", "credentials", "netbanking", "kyc", "ओटीपी", "पासवर्ड", "पिन", "कार्ड", "खाता", "केवाईसी", "खाते", "बँक"],
    desc: "Explicitly requests private information like OTPs, passwords, or banking details."
  },
  SUSPICIOUS_ACTION: {
    title: "Suspicious Instruction / Click Demand",
    points: 20,
    category: "Malicious Action",
    keywords: ["click here", "click below", "visit link", "download app", "verify now", "login here", "call immediately", "क्लिक करें", "लिंक पर जाएं", "सत्यापित करें", "क्लिक करा", "लिंकवर जा", "सत्यापित करा"],
    desc: "Demands clicking unverified external links or downloading suspicious applications."
  },
  IMPERSONATION: {
    title: "Brand / Authority Impersonation",
    points: 15,
    category: "Impersonation",
    keywords: ["rbi", "sbi", "hdfc", "icici", "income tax", "electricity", "fedex", "amazon", "whatsapp", "telegram", "police", "bank", "बैंक", "बँक", "आरबीआय", "एसबीआय"],
    desc: "Impersonates recognized financial institutions, government departments, or trusted services."
  }
};

export function detectLanguageLocal(text) {
  const devanagariMatches = (text || "").match(/[\u0900-\u097F]/g);
  if (devanagariMatches && devanagariMatches.length > 3) {
    const marathiWords = ["तुमचे", "खालील", "तातडीने", "झाले", "आहे", "करा", "खाते", "लिंकवर", "अकाऊंट", "कृपया", "बँक"];
    const marathiHits = marathiWords.filter(w => text.includes(w)).length;
    if (marathiHits > 0 || text.includes("तुमचे") || text.includes("करा") || text.includes("लिंकवर")) {
      return "Marathi";
    }
    return "Hindi";
  }
  return "English";
}

export function analyzeMessageLocal(messageText) {
  const textClean = (messageText || "").trim();
  if (!textClean) {
    return {
      error: "Message text cannot be empty.",
      risk_score: 0,
      risk_level: "SAFE",
      threat_type: "None",
      detected_language: "Unknown",
      indicators: [],
      links_found: [],
      explanation: "No message entered.",
      recommendation: "Please paste a message or email body."
    };
  }

  const detectedLang = detectLanguageLocal(textClean);
  const textLower = textClean.toLowerCase();

  const indicators = [];
  let totalScore = 0;

  for (const [code, rule] of Object.entries(MESSAGE_RULES)) {
    const matched = rule.keywords.filter(kw => textLower.includes(kw.toLowerCase()));
    if (matched.length > 0) {
      const uniqueMatched = Array.from(new Set(matched)).slice(0, 3);
      totalScore += rule.points;
      indicators.push({
        code,
        title: rule.title,
        points: rule.points,
        category: rule.category,
        description: `${rule.desc} (Matched terms: ${uniqueMatched.join(", ")})`
      });
    }
  }

  // Check embedded links
  const urlRegex = /https?:\/\/[^\s>"]+|www\.[^\s>"]+/gi;
  const linksFound = textClean.match(urlRegex) || [];
  const analyzedLinks = [];

  if (linksFound.length > 0) {
    totalScore += 12;
    indicators.push({
      code: "EMBEDDED_LINK",
      title: "Embedded Hyperlink Found",
      points: 12,
      category: "External Vector",
      description: `Found ${linksFound.length} embedded link(s). Phishing campaigns rely heavily on embedded links for credential theft.`
    });

    linksFound.forEach(link => {
      const res = analyzeUrlLocal(link);
      analyzedLinks.push(res);
      if (res.risk_score > 60) {
        totalScore += 15;
      }
    });
  }

  const finalScore = Math.min(totalScore, 100);

  let riskLevel = "SAFE";
  if (finalScore >= 85) riskLevel = "CRITICAL";
  else if (finalScore >= 65) riskLevel = "HIGH";
  else if (finalScore >= 40) riskLevel = "MEDIUM";
  else if (finalScore >= 20) riskLevel = "LOW";

  const codes = indicators.map(i => i.code);
  let threatType = "Legitimate / Low Risk Message";
  if (codes.includes("SENSITIVE_INFO") && codes.includes("EMBEDDED_LINK")) {
    threatType = "High-Risk Credential Harvesting Phish";
  } else if (codes.includes("FEAR_SUSPENSION") && codes.includes("URGENCY")) {
    threatType = "Urgent Account Impersonation Scam";
  } else if (codes.includes("REWARD_PRIZE")) {
    threatType = "Financial Bait / Lottery Scam";
  } else if (finalScore >= 40) {
    threatType = "Suspicious Phishing Message";
  }

  let explanation = `The message in ${detectedLang} appears clean with no significant threat indicators (Score: ${finalScore}/100).`;
  let recommendation = "Standard security caution recommended.";

  if (riskLevel === "CRITICAL" || riskLevel === "HIGH") {
    explanation = `CyberShield AI detected severe phishing signatures in this ${detectedLang} message (Risk Score: ${finalScore}/100). It employs coercive pressure, threat language, or requests sensitive credentials.`;
    recommendation = "DO NOT click links, call numbers, or share OTPs. Block and report the sender immediately.";
  } else if (riskLevel === "MEDIUM") {
    explanation = `Moderate threat indicators identified (${finalScore}/100) in ${detectedLang} text. Contains characteristics common in promotional spam or unsolicited requests.`;
    recommendation = "Verify the authenticity of the message with the official organization.";
  } else if (riskLevel === "LOW") {
    explanation = `Low risk score (${finalScore}/100). Minimal suspicious indicators found in ${detectedLang} message.`;
    recommendation = "Exercise standard caution when receiving unexpected communications.";
  }

  return {
    message: textClean,
    detected_language: detectedLang,
    risk_score: finalScore,
    risk_level: riskLevel,
    threat_type: threatType,
    indicators,
    links_found: analyzedLinks,
    explanation,
    recommendation,
    analysis_type: "Local Multilingual Phishing Engine (JS Fallback)"
  };
}
