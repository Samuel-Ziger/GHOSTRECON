export const UA = 'GHOSTRECON/1.0 (+https://example.local; passive OSINT)';

export const limits = {
  waybackCollapseLimit: 3000,
  maxJsFetch: 18,
  probeConcurrency: 6,
  probeTimeoutMs: 12000,
  maxBodySnippet: 65536,
  /** Máx. queries CSE por run (quota grátis ~100/dia) */
  googleCseMaxQueries: 20,
  googleCseDelayMs: 650,
};

export const interestingPathRe =
  /\/(api|admin|login|signin|dashboard|internal|debug|dev|test|graphql|swagger|actuator|v1|v2|oauth|callback)(\/|$)/i;

export const sensitiveExtRe = /\.(env|git|bak|old|sql|db|sqlite|pem|key|config|json|ya?ml|log)$/i;
