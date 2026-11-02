'use strict';

const assert = require('assert');
const { FindingLifecycle, fromJSON } = require('../src/finding-lifecycle');

const finding = new FindingLifecycle({ title: 'Cross-user order access', target: '/api/orders/2' });
assert.strictEqual(finding.status, 'lead');
finding.transition('candidate', 'runtime differential observed', { identities: ['alice', 'bob'] });
finding.transition('proven', 'ownership marker and control response reproduced');
finding.transition('accepted', 'human review confirmed impact');
assert.strictEqual(finding.toJSON().history.length, 4);

assert.throws(() => finding.transition('refuted', ''), /reason is required/);
assert.throws(() => finding.transition('lead', 'reset'), /invalid finding transition/);

const restored = fromJSON(finding.toJSON());
assert.strictEqual(restored.status, 'accepted');
assert.deepStrictEqual(restored.toJSON().history, finding.toJSON().history);

const review = new FindingLifecycle({ title: 'Ambiguous timing lead' });
review.transition('needs-review', 'timing signal lacks stable baseline');
review.transition('candidate', 'manual review requested a controlled replay');
assert.strictEqual(review.status, 'candidate');

console.log('finding-lifecycle: ok');
