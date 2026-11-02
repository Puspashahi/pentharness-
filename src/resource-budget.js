'use strict';

class ResourceBudget {
  constructor({ maxRequests = Infinity, maxBytes = Infinity, maxTimeMs = Infinity, maxConcurrency = 1 } = {}) {
    this.limits = { maxRequests, maxBytes, maxTimeMs, maxConcurrency };
    this.startedAt = Date.now();
    this.requests = 0;
    this.bytes = 0;
    this.active = 0;
  }

  check(extraBytes = 0) {
    if (this.requests >= this.limits.maxRequests) throw new Error('resource budget exceeded: requests');
    if (this.bytes + extraBytes > this.limits.maxBytes) throw new Error('resource budget exceeded: bytes');
    if (Date.now() - this.startedAt >= this.limits.maxTimeMs) throw new Error('resource budget exceeded: time');
    if (this.active >= this.limits.maxConcurrency) throw new Error('resource budget exceeded: concurrency');
  }

  acquire(extraBytes = 0) {
    this.check(extraBytes);
    this.active++;
    this.requests++;
    this.bytes += extraBytes;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.active--;
      }
    };
  }

  toJSON() {
    return { limits: this.limits, requests: this.requests, bytes: this.bytes, active: this.active, elapsedMs: Date.now() - this.startedAt };
  }
}

module.exports = { ResourceBudget };
