'use strict';

/**
 * Relationship model for multi-tenant authorization research.
 *
 * This is intentionally evidence-first: inferred edges produce test plans and
 * candidates, never confirmed findings. Records can come from captures,
 * fixtures, or a researcher-maintained application model.
 */

const TYPES = new Set(['user', 'organization', 'tenant', 'project', 'resource', 'role', 'invitation', 'share']);

function idOf(record, type) {
  const keys = {
    user: ['userId', 'user_id', 'actor', 'identity', 'id'],
    organization: ['organizationId', 'organization_id', 'orgId', 'org_id', 'tenantId', 'tenant_id'],
    tenant: ['tenantId', 'tenant_id', 'organizationId', 'organization_id', 'id'],
    project: ['projectId', 'project_id', 'id'],
    resource: ['resourceId', 'resource_id', 'objectId', 'object_id', 'id'],
    role: ['role', 'roleId', 'role_id'],
    invitation: ['invitationId', 'invitation_id', 'id'],
    share: ['shareId', 'share_id', 'id'],
  };
  for (const key of keys[type] || []) if (record[key] != null && String(record[key]) !== '') return String(record[key]);
  return null;
}

function tenantOf(record) {
  return idOf(record, 'tenant') || idOf(record, 'organization');
}

class TenantGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = [];
    this.observations = [];
    this.contradictions = [];
  }

  node(type, id, attrs = {}) {
    if (!TYPES.has(type) || !id) return null;
    const key = `${type}:${id}`;
    const current = this.nodes.get(key) || { key, type, id, attrs: {} };
    current.attrs = { ...current.attrs, ...attrs };
    this.nodes.set(key, current);
    return current;
  }

  edge(fromType, fromId, relation, toType, toId, evidence = {}) {
    if (!this.node(fromType, fromId) || !this.node(toType, toId)) return;
    const key = `${fromType}:${fromId}|${relation}|${toType}:${toId}`;
    if (!this.edges.some((e) => e.key === key)) this.edges.push({
      key, from: `${fromType}:${fromId}`, relation, to: `${toType}:${toId}`, evidence,
    });
  }

  add(record) {
    const r = { ...record };
    const user = idOf(r, 'user');
    const tenant = tenantOf(r);
    const project = idOf(r, 'project');
    const resource = idOf(r, 'resource');
    const role = idOf(r, 'role');
    const invitation = idOf(r, 'invitation');
    const share = idOf(r, 'share');
    if (user) this.node('user', user, { label: r.email || r.username, role: r.role });
    if (tenant) this.node('tenant', tenant, { name: r.organizationName || r.tenantName });
    if (project) this.node('project', project);
    if (resource) this.node('resource', resource, { kind: r.resourceType || r.kind });
    if (role) this.node('role', role);
    if (invitation) this.node('invitation', invitation);
    if (share) this.node('share', share);
    if (user && tenant) this.edge('user', user, 'member_of', 'tenant', tenant, { source: r.source });
    if (project && tenant) this.edge('project', project, 'belongs_to', 'tenant', tenant, { source: r.source });
    const resourceTenant = r.resourceTenantId || r.resource_tenant_id || r.ownerTenantId || r.owner_tenant_id
      || (r.owner === true ? tenant : null);
    if (resource && resourceTenant) this.edge('resource', resource, 'belongs_to', 'tenant', String(resourceTenant), { source: r.source });
    if (resource && project) this.edge('resource', resource, 'in_project', 'project', project, { source: r.source });
    if (user && resource && (r.owner === true || r.ownerId === user || r.owner_id === user)) {
      this.edge('user', user, 'owns', 'resource', resource, { source: r.source });
    }
    if (user && role) this.edge('user', user, 'has_role', 'role', role, { source: r.source });
    if (invitation && tenant) this.edge('invitation', invitation, 'for_tenant', 'tenant', tenant, { source: r.source });
    if (share && resource) this.edge('share', share, 'shares', 'resource', resource, { source: r.source });
    if (user && share) this.edge('user', user, 'uses_share', 'share', share, { source: r.source });
    if (r.access != null && (resource || project)) {
      this.observations.push({
        actor: user || 'unknown',
        tenant: tenant || null,
        target: resource ? `resource:${resource}` : `project:${project}`,
        access: String(r.access),
        status: r.status,
        source: r.source,
      });
    }
    return this;
  }

  infer() {
    const membership = new Map();
    for (const e of this.edges.filter((x) => x.relation === 'member_of')) {
      if (!membership.has(e.from)) membership.set(e.from, new Set());
      membership.get(e.from).add(e.to);
    }
    const resources = [...this.nodes.values()].filter((n) => n.type === 'resource');
    const candidates = [];
    for (const resource of resources) {
      const ownerTenants = this.edges.filter((e) => e.from === resource.key && e.relation === 'belongs_to').map((e) => e.to);
      if (!ownerTenants.length) continue;
      for (const [user, tenants] of membership) {
        const foreign = [...tenants].filter((t) => !ownerTenants.includes(t));
        if (!foreign.length) continue;
        candidates.push({
          kind: 'cross-tenant-access',
          target: resource.key,
          actor: user,
          owner_tenants: ownerTenants,
          actor_tenants: foreign,
          confidence: 'candidate',
          reason: 'resource and actor are modeled in different tenant boundaries',
          proof_needed: [
            'replay the identical request with the foreign-tenant identity',
            'verify the response contains the target resource, not a public shell',
            'confirm the resource is not intentionally shared or invitation-backed',
          ],
        });
      }
    }
    const byKey = new Map();
    for (const o of this.observations) {
      const key = `${o.actor}|${o.target}`;
      const prev = byKey.get(key);
      if (prev && prev.access !== o.access) {
        this.contradictions.push({ key, first: prev, second: o, reason: 'same actor-target pair has inconsistent access observations' });
      } else if (!prev) byKey.set(key, o);
    }
    return { candidates, contradictions: this.contradictions.slice() };
  }

  plan() {
    const inferred = this.infer();
    return {
      nodes: [...this.nodes.values()],
      edges: this.edges.slice(),
      candidates: inferred.candidates,
      contradictions: inferred.contradictions,
      proof_policy: 'inferred relationships are hypotheses; no vulnerability is confirmed without reproducible runtime proof',
    };
  }
}

function build(records = []) {
  const graph = new TenantGraph();
  for (const record of records) graph.add(record);
  return graph.plan();
}

module.exports = { TenantGraph, build, TYPES, idOf, tenantOf };
