# WebDAV Specification Reference (RFC 4918)

> Distilled from RFC 4918 for implementation by LLM coding agents.
> This is a concise, actionable reference — not a verbatim copy.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Core Concepts](#2-core-concepts)
3. [Property Model](#3-property-model)
4. [Collection Model](#4-collection-model)
5. [Locking Model](#5-locking-model)
6. [HTTP Methods](#6-http-methods)
7. [WebDAV Headers](#7-webdav-headers)
8. [Status Codes](#8-status-codes)
9. [Multi-Status Response Format](#9-multi-status-response-format)
10. [XML Element Reference](#10-xml-element-reference)
11. [DAV Properties](#11-dav-properties)
12. [Precondition/Postcondition Codes](#12-preconditionpostcondition-codes)
13. [Compliance Classes](#13-compliance-classes)
14. [General Rules](#14-general-rules)

---

## 1. Overview

WebDAV (Web Distributed Authoring and Versioning) extends HTTP/1.1 with:
- **Properties** — name/value metadata on resources (XML-based)
- **Collections** — container resources (like directories)
- **Locking** — prevent lost updates via exclusive/shared locks
- **Namespace operations** — COPY and MOVE resources

**XML namespace:** `DAV:` (used for all WebDAV-defined elements and properties)

**Content-Type for XML bodies:** `application/xml` (MUST accept both `text/xml` and `application/xml`)

---

## 2. Core Concepts

### Resources
- Every URL maps to a resource
- Resources can be **collections** (containers) or **non-collections** (files)
- A resource's type is indicated by `DAV:resourcetype` property

### Terminology
| Term | Meaning |
|------|---------|
| Collection | Resource that contains mappings from path segments to child resources |
| Internal Member | Direct child of a collection |
| Member | Any descendant (recursive) |
| Live Property | Server-enforced semantics and syntax |
| Dead Property | Client-managed; server stores verbatim |
| Principal | User or computational actor |
| Lock Token | URI uniquely identifying a lock |
| State Token | URI representing resource state (lock tokens are the only kind) |

---

## 3. Property Model

### Property Names
- Identified by XML namespace + local name (e.g., `DAV:creationdate`)
- Namespace prevents collisions
- Flat namespace (no hierarchy between properties)
- Cannot define same property twice on a single resource

### Property Values
- Always well-formed XML fragments
- Value appears inside the property name element
- Can be text-only, mixed content, or empty
- Empty property (`<D:displayname/>`) is different from non-existent property

### Live vs Dead Properties

| Aspect | Live | Dead |
|--------|------|------|
| Semantics enforced by | Server | Client |
| Value maintained by | Server (or client with server validation) | Client |
| Examples | `DAV:getcontentlength`, `DAV:getetag` | Any custom property |
| PROPPATCH | May reject changes (protected) | MUST accept arbitrary values |

### XML Preservation for Dead Properties

Servers MUST preserve these XML Information Items:
- Element: namespace name, local name, attributes, children (element or character)
- Attribute: namespace name, local name, normalized value
- Character: character code
- SHOULD preserve: prefix

Servers MUST ignore `xml:space` attribute. Whitespace in values is significant.

---

## 4. Collection Model

### URL Conventions
- Collection URLs SHOULD end with trailing slash `/`
- Server MAY handle requests without trailing slash as if it were present
- Server SHOULD return `Content-Location` header pointing to URL with `/`
- Use `DAV:resourcetype` property (not URL) to determine if resource is a collection

### Collection State
- Set of mappings: path segment → resource
- Each path segment maps to at most one resource
- Plus properties on the collection itself
- MAY have entity body returned by GET

### Namespace Consistency
- For WebDAV resources A (at URL `U`) and B (at URL `U/SEGMENT`): A MUST be a collection containing mapping from SEGMENT to B
- Methods MUST NOT produce results causing namespace inconsistencies
- Intermediate collections are NOT auto-created (methods fail with 409 if ancestors missing)

### Depth Header Values
| Value | Scope |
|-------|-------|
| `0` | Only the collection itself |
| `1` | Collection and its direct children |
| `infinity` | Collection and all descendants recursively |

---

## 5. Locking Model

### Lock Types
Only one access type defined: **write lock**

### Lock Scopes
| Scope | Behaviour |
|-------|-----------|
| **Exclusive** | Only the lock holder can modify. Conflicts with ALL other locks. |
| **Shared** | Multiple principals can hold locks simultaneously. Each gets unique token. |

### Lock Compatibility Table

| Current State | Shared Lock Request | Exclusive Lock Request |
|---------------|--------------------|-----------------------|
| None | ✅ Granted | ✅ Granted |
| Shared Lock | ✅ Granted | ❌ Denied |
| Exclusive Lock | ❌ Denied | ❌ Denied |

### Lock Model Rules

1. A lock **directly** or **indirectly** locks a resource
2. LOCK on a URL creates a new lock with that URL as **lock-root**
3. If URL is unmapped, creates an empty resource and locks it
4. Exclusive lock conflicts with ANY other lock on the same resource
5. Depth-infinity lock on collection → all members indirectly locked
6. Each lock has a globally unique **lock token** (URI)
7. UNLOCK deletes the lock with the specified token
8. Lock tokens are "submitted" via `If` header
9. If lock-root becomes unmapped URL → lock is deleted

### Lock Tokens
- Format: URIs, typically `urn:uuid:<UUID>` (RFC 4122)
- Also valid: `opaquelocktoken:` scheme
- Server generates; client MUST NOT interpret
- Returned in `Lock-Token` response header and response body
- MUST be unique across all resources for all time

### Lock Timeouts
- Client suggests timeout in `Timeout` header; server chooses actual value
- Format: `Second-<n>` or `Infinite`
- Maximum: `2^32-1` seconds
- Timeout resets on successful refresh
- Expired lock SHOULD be removed (as if server did UNLOCK)

### Write Lock Rules
- Lock holder's identity MUST be checked (authenticated principal must match lock creator)
- Lock token MUST be submitted in `If` header for any operation that modifies a locked resource
- Write lock protects: resource content, properties, and lock state
- For locked collections: adding/removing members requires lock token submission
- COPY does not move locks; MOVE does not move locks to destination

---

## 6. HTTP Methods

### 6.1 OPTIONS

Standard HTTP OPTIONS. WebDAV-specific behaviour:

**Response headers:**
- `DAV: 1` (MUST for Class 1)
- `DAV: 1, 2` (if locking supported — Class 2)
- `DAV: 1, 3` or `DAV: 1, 2, 3` (RFC 4918 compliant — Class 3)
- `Allow:` header listing supported methods

**Implementation notes:**
- MUST return `DAV` header on all OPTIONS responses for WebDAV-compliant resources
- Non-WebDAV resources SHOULD NOT advertise WebDAV support

---

### 6.2 PROPFIND

Retrieves properties on a resource (and potentially its members).

**Request:**
- Method: `PROPFIND`
- Headers: `Depth: 0|1|infinity` (MUST be present; default treated as `infinity`)
- Content-Type: `application/xml`
- Body: `<propfind>` element (one of):
  - `<prop>` — request specific named properties
  - `<allprop/>` — all dead properties + live properties defined in RFC 4918
  - `<allprop/>` + `<include>` — allprop plus additional named live properties
  - `<propname/>` — list all property names (no values)
  - Empty body → treated as `allprop`

**Request body examples:**

```xml
<!-- Named properties -->
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:displayname/>
    <D:getcontentlength/>
  </D:prop>
</D:propfind>

<!-- All property names -->
<D:propfind xmlns:D="DAV:">
  <D:propname/>
</D:propfind>

<!-- All properties -->
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>

<!-- Allprop with extras -->
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
  <D:include>
    <D:supported-live-property-set/>
  </D:include>
</D:propfind>
```

**Response:**
- Status: `207 Multi-Status`
- Content-Type: `application/xml`
- Body: `<multistatus>` with `<response>` for each resource
- Each `<response>` contains `<href>` and one or more `<propstat>` elements
- Each `<propstat>` groups properties by status code

**Response body structure:**

```xml
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/path/to/resource</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>My File</D:displayname>
        <D:getcontentlength>1234</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
    <D:propstat>
      <D:prop>
        <D:getcontentlanguage/>
      </D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
```

**Status codes in propstat:**
- `200 OK` — property exists, value returned
- `401 Unauthorized` — need auth to view
- `403 Forbidden` — cannot view regardless of auth
- `404 Not Found` — property does not exist

**Method status codes:**
- `207 Multi-Status` — normal response
- `403 Forbidden` — MAY reject `Depth: infinity` with `propfind-finite-depth` precondition

**MUST requirements:**
- All DAV-compliant resources MUST support PROPFIND
- Servers MUST support Depth 0 and 1; SHOULD support infinity
- MUST return `<response>` for each member URL
- Non-existent requested property → 404 in propstat
- Safe and idempotent

---

### 6.3 PROPPATCH

Sets and/or removes properties on a resource.

**Request:**
- Method: `PROPPATCH`
- Content-Type: `application/xml`
- Body: `<propertyupdate>` containing `<set>` and/or `<remove>` elements

**Request body:**

```xml
<D:propertyupdate xmlns:D="DAV:">
  <D:set>
    <D:prop>
      <D:displayname>New Name</D:displayname>
    </D:prop>
  </D:set>
  <D:remove>
    <D:prop>
      <x:custom xmlns:x="http://example.com/ns/"/>
    </D:prop>
  </D:remove>
</D:propertyupdate>
```

**Response:**
- Status: `207 Multi-Status`
- Body: `<multistatus>` with propstat results

**Key rules:**
- Instructions processed in document order
- MUST be atomic: ALL succeed or ALL fail (rollback)
- Removing non-existent property is NOT an error
- DAV-compliant resources SHOULD support setting arbitrary dead properties
- Idempotent, not safe; responses MUST NOT be cached

**Status codes in propstat:**
- `200 OK` — property change succeeded
- `403 Forbidden` — cannot alter property (e.g., protected property → use `cannot-modify-protected-property`)
- `409 Conflict` — inappropriate value semantics
- `424 Failed Dependency` — would have succeeded but another change failed
- `507 Insufficient Storage`

---

### 6.4 MKCOL

Creates a new collection.

**Request:**
- Method: `MKCOL`
- No body required (body behaviour undefined but limited to collection-related operations)

**Key rules:**
- Request-URI MUST NOT already be mapped → 405 Method Not Allowed
- All ancestor collections MUST already exist → 409 Conflict
- SHOULD create empty collection (no members)
- Idempotent, not safe; responses MUST NOT be cached

**Status codes:**
- `201 Created` — collection created
- `403 Forbidden` — server doesn't allow collection at this location
- `405 Method Not Allowed` — URL already mapped
- `409 Conflict` — intermediate collections missing
- `415 Unsupported Media Type` — body type not supported
- `507 Insufficient Storage`

---

### 6.5 GET / HEAD

**For non-collections:** Standard HTTP behaviour.

**For collections:**
- GET MAY return an HTML listing, index page, or anything else
- No requirement to correlate GET response with collection membership
- HEAD behaves as GET without body

---

### 6.6 PUT

Creates or replaces a non-collection resource.

**For non-collection resources:**
- Replaces GET response entity of existing resource
- Properties may be recomputed but not otherwise affected
- Client SHOULD provide Content-Type
- If creating new resource: parent collection MUST exist → 409 Conflict

**For collections:**
- Behaviour undefined; MAY return 405 Method Not Allowed
- Use MKCOL to create collections

**Status codes:**
- `201 Created` — new resource created
- `204 No Content` — existing resource replaced
- `409 Conflict` — no parent collection

---

### 6.7 DELETE

Deletes a resource.

**For non-collections:**
- Removes URL-to-resource mapping
- Subsequent GET/HEAD/PROPFIND → 404
- MUST destroy locks rooted on deleted resource

**For collections:**
- MUST act as `Depth: infinity` (client MUST NOT send other depth values)
- Deletes collection and ALL members recursively
- If any member cannot be deleted → ancestors MUST NOT be deleted (namespace consistency)
- Errors on members → 207 Multi-Status response

**Key rules:**
- On success: URL returns 404 for subsequent requests
- Multi-Status SHOULD NOT include `424 Failed Dependency` (client infers from parent failure)
- SHOULD NOT include `204 No Content` in Multi-Status (it's the default success)

**Status codes:**
- `204 No Content` — success
- `207 Multi-Status` — partial failure on collection members
- `423 Locked` — resource or member locked

---

### 6.8 COPY

Creates a duplicate of the source resource at the destination.

**Request:**
- Method: `COPY`
- Headers:
  - `Destination: <absolute-URI>` (REQUIRED)
  - `Overwrite: T|F` (default `T`)
  - `Depth: 0|infinity` (default `infinity` for collections)

**For non-collections:**
- Creates new resource at destination matching source state/behaviour

**For collections:**
- `Depth: infinity` — copies collection and all members recursively
- `Depth: 0` — copies collection and its properties only (not members)
- Destination header adjusted for members (e.g., `/a/c/d` → `/b/c/d`)

**Properties:**
- Dead properties SHOULD be duplicated
- Live properties SHOULD behave identically at destination (not necessarily same values)
- Server SHOULD NOT convert live → dead properties

**Overwrite behaviour:**
- `Overwrite: F` + destination exists → MUST fail with 412
- `Overwrite: T` + destination exists → delete destination first, then copy
- Collection overwrite: destination membership = source membership (no merging)

**Error handling:**
- Error on internal collection → skip that subtree
- SHOULD continue copying other subtrees
- Errors on members → 207 Multi-Status

**Status codes:**
- `201 Created` — new resource at destination
- `204 No Content` — existing destination overwritten
- `207 Multi-Status` — partial failures
- `403 Forbidden` — e.g., source = destination
- `409 Conflict` — intermediate collections missing
- `412 Precondition Failed` — Overwrite: F and destination exists
- `423 Locked` — destination locked
- `502 Bad Gateway` — cross-server copy not supported
- `507 Insufficient Storage`

**MUST:** All WebDAV resources MUST support COPY. Idempotent, not safe; MUST NOT cache.

---

### 6.9 MOVE

Logical equivalent of COPY + delete source (in a single atomic operation).

**Request:**
- Method: `MOVE`
- Headers:
  - `Destination: <absolute-URI>` (REQUIRED)
  - `Overwrite: T|F` (default `T`)
  - Depth is always `infinity` for collections (MUST NOT send other value)

**Properties:**
- Live properties SHOULD move with the resource (same behaviour, possibly different values)
- `DAV:creationdate` SHOULD be preserved (MOVE is conceptually rename)
- Dead properties MUST be moved

**Overwrite behaviour:**
- `Overwrite: T` + destination exists → DELETE destination first
- `Overwrite: F` + destination exists → fail

**Error handling:**
- Same as COPY for collection members
- Error on internal collection → skip subtree, continue others
- MUST create consistent namespace at BOTH source and destination

**Status codes:**
- `201 Created` — moved to new URL
- `204 No Content` — moved to existing URL (overwritten)
- `207 Multi-Status` — partial failures
- `403 Forbidden` — e.g., source = destination
- `409 Conflict` — intermediates missing or live properties can't be preserved
- `412 Precondition Failed` — Overwrite: F and destination exists
- `423 Locked` — source, destination, or parent locked
- `502 Bad Gateway` — cross-server move

**MUST:** All WebDAV resources MUST support MOVE. Idempotent, not safe; MUST NOT cache.

---

### 6.10 LOCK

Creates a new lock or refreshes an existing lock.

#### Creating a Lock

**Request:**
- Method: `LOCK`
- Headers:
  - `Depth: 0|infinity` (default `infinity`)
  - `Timeout: Second-<n>` or `Infinite` (optional; server chooses)
- Content-Type: `application/xml`
- Body: `<lockinfo>` element

**Request body:**

```xml
<D:lockinfo xmlns:D="DAV:">
  <D:lockscope><D:exclusive/></D:lockscope>
  <D:locktype><D:write/></D:locktype>
  <D:owner>
    <D:href>http://example.org/~user/contact.html</D:href>
  </D:owner>
</D:lockinfo>
```

**Response (success):**
- Status: `200 OK` (existing resource) or `201 Created` (unmapped URL)
- `Lock-Token: <urn:uuid:...>` header
- Body: `<prop>` containing `<lockdiscovery>` with full lock info

**Response body:**

```xml
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>infinity</D:depth>
      <D:owner>
        <D:href>http://example.org/~user/contact.html</D:href>
      </D:owner>
      <D:timeout>Second-604800</D:timeout>
      <D:locktoken>
        <D:href>urn:uuid:e71d4fae-5dec-22d6-fea5-00a0c91e6be4</D:href>
      </D:locktoken>
      <D:lockroot>
        <D:href>http://example.com/resource</D:href>
      </D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>
```

#### Refreshing a Lock

**Request:**
- Method: `LOCK`
- No body
- `If: (<lock-token>)` header (MUST specify single lock token)
- `Timeout:` header (optional, server MAY accept new timeout)

**Response:**
- Status: `200 OK`
- No `Lock-Token` header in response
- Body: updated `<lockdiscovery>`

#### Locking Unmapped URLs
- Creates an empty resource (not a collection)
- MUST respond to GET with 204 or 200 with zero-length body
- Empty resource appears in PROPFIND responses

**Status codes:**
- `200 OK` — lock created/refreshed
- `201 Created` — lock on unmapped URL created new resource
- `207 Multi-Status` — depth lock failed on some members
- `409 Conflict` — intermediates missing
- `412 Precondition Failed` + `lock-token-matches-request-uri` — refresh token not in scope
- `423 Locked` + `no-conflicting-lock` — conflicting lock exists

**MUST:** Neither idempotent nor safe; MUST NOT cache.

---

### 6.11 UNLOCK

Removes a lock.

**Request:**
- Method: `UNLOCK`
- `Lock-Token: <token>` header (REQUIRED)
- Request-URI MUST be within lock scope

**Response:**
- Status: `204 No Content` (success)

**Key rules:**
- Removes lock entirely from all resources in its scope
- If not all resources can be unlocked → MUST fail
- `If` header not needed for lock token (but if present, acts as normal conditional)
- Idempotent, not safe; MUST NOT cache

**Status codes:**
- `204 No Content` — success
- `400 Bad Request` — no lock token provided
- `403 Forbidden` — not permitted to remove lock
- `409 Conflict` + `lock-token-matches-request-uri` — URI not in lock scope

---

## 7. WebDAV Headers

### 7.1 DAV (Response)

```
DAV: 1
DAV: 1, 2
DAV: 1, 2, 3
```

- Indicates compliance classes supported by the resource
- MUST be returned on OPTIONS responses
- Value: comma-separated list of compliance class identifiers

### 7.2 Depth (Request)

```
Depth: 0 | 1 | infinity
```

- Controls scope of operation on collections
- Only used with methods that explicitly support it
- Default value varies by method (see individual methods)

### 7.3 Destination (Request)

```
Destination: http://example.com/target/path
```

- Used with COPY and MOVE
- MUST be an absolute URI or path-absolute
- If cross-server and unsupported → fail

### 7.4 If (Request)

```
If: (<lock-token>) ([etag])
If: <resource-url> (<lock-token>)
```

**Purpose (dual):**
1. Conditional: request fails with 412 if condition evaluates to false
2. Submits lock tokens (indicates client knowledge of the token)

**Syntax:**
- **No-tag list:** conditions apply to Request-URI
- **Tagged list:** conditions apply to the specified resource URL
- Cannot mix tagged and untagged in one header
- Conditions within a list: AND (all must be true)
- Multiple lists: OR (any list succeeds)
- `Not` prefix reverses a condition

**Examples:**
```
If: (<urn:uuid:token1>)
If: (<urn:uuid:token1> ["etag-value"])
If: (Not <urn:uuid:token1>)
If: <http://example.com/res> (<urn:uuid:token1>)
```

**Always-true trick:** `(Not <DAV:no-lock>)` — `DAV:no-lock` never matches, so Not makes it true.

### 7.5 Lock-Token

**Request (UNLOCK):**
```
Lock-Token: <urn:uuid:...>
```

**Response (LOCK create):**
```
Lock-Token: <urn:uuid:...>
```

### 7.6 Overwrite (Request)

```
Overwrite: T | F
```

- Used with COPY and MOVE
- Default: `T` (overwrite)
- `F` → fail with 412 if destination exists
- All DAV-compliant resources MUST support this header

### 7.7 Timeout (Request)

```
Timeout: Second-3600
Timeout: Infinite, Second-4100000000
```

- Used with LOCK only
- Server not required to honour
- Comma-separated list of preferred timeouts (server picks one)
- Max: `2^32 - 1` seconds

---

## 8. Status Codes

### WebDAV-Specific Status Codes

| Code | Name | Meaning |
|------|------|---------|
| **207** | Multi-Status | Response body contains status for multiple resources |
| **422** | Unprocessable Entity | Well-formed XML but semantically erroneous |
| **423** | Locked | Source or destination resource is locked |
| **424** | Failed Dependency | Action failed because another action it depended on failed |
| **507** | Insufficient Storage | Server lacks space to complete the request |

### Commonly Used HTTP Status Codes in WebDAV

| Code | Typical Use |
|------|-------------|
| `200 OK` | Success (PROPFIND, LOCK, etc.) |
| `201 Created` | New resource created (PUT, MKCOL, COPY, MOVE, LOCK) |
| `204 No Content` | Success with no body (DELETE, UNLOCK, PUT overwrite) |
| `207 Multi-Status` | Complex operation results |
| `400 Bad Request` | Malformed XML, missing lock token |
| `403 Forbidden` | Operation not allowed |
| `404 Not Found` | Resource or property doesn't exist |
| `405 Method Not Allowed` | MKCOL on existing resource, PUT on collection |
| `409 Conflict` | Missing intermediate collections |
| `412 Precondition Failed` | If/Overwrite header condition failed |
| `415 Unsupported Media Type` | Body present when not expected |
| `423 Locked` | Resource locked, token not submitted |
| `424 Failed Dependency` | Would have succeeded but sibling operation failed |
| `502 Bad Gateway` | Cross-server COPY/MOVE failed |
| `507 Insufficient Storage` | No space |

### Error Handling Precedence
1. Authorization checks FIRST
2. Then conditional headers (If, Overwrite, etc.)
3. Then method-specific processing

---

## 9. Multi-Status Response Format

### Structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <!-- Format 1: Status on whole resource -->
  <D:response>
    <D:href>/path/resource</D:href>
    <D:status>HTTP/1.1 423 Locked</D:status>
    <D:error><D:lock-token-submitted/></D:error>
  </D:response>

  <!-- Format 2: Property-level status (PROPFIND/PROPPATCH) -->
  <D:response>
    <D:href>/path/resource</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>file.txt</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
    <D:propstat>
      <D:prop><D:getcontentlanguage/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>

  <D:responsedescription>Optional description</D:responsedescription>
</D:multistatus>
```

### Rules
- Each `<response>` MUST have an `<href>`
- Same href MUST NOT appear twice in a multistatus
- Uses either `<status>` (resource-level) or `<propstat>` (property-level), not both
- `<href>` values must be consistent: all absolute URIs or all absolute paths
- `<responsedescription>` is optional, for human-readable messages
- 100-series status codes SHOULD NOT appear
- `<location>` element used for redirect responses within multistatus

### Error Minimisation
For DELETE, COPY, MOVE multi-status responses:
- SHOULD NOT include `424 Failed Dependency` — client infers from parent errors
- SHOULD NOT include `204 No Content` / `201 Created` — these are default success

---

## 10. XML Element Reference

All elements in `DAV:` namespace.

### Request Elements

| Element | Contains | Used In |
|---------|----------|---------|
| `propfind` | `propname` \| (`allprop`, `include`?) \| `prop` | PROPFIND body |
| `propname` | EMPTY | PROPFIND (list names only) |
| `allprop` | EMPTY | PROPFIND (all properties) |
| `include` | property name elements | PROPFIND with allprop |
| `propertyupdate` | (`set` \| `remove`)+ | PROPPATCH body |
| `set` | `prop` | PROPPATCH (set values) |
| `remove` | `prop` | PROPPATCH (remove properties) |
| `lockinfo` | `lockscope`, `locktype`, `owner`? | LOCK body |

### Response Elements

| Element | Contains | Used In |
|---------|----------|---------|
| `multistatus` | `response`*, `responsedescription`? | 207 response body |
| `response` | `href`, (`status` \| `propstat`+), `error`?, `responsedescription`?, `location`? | multistatus |
| `propstat` | `prop`, `status`, `error`?, `responsedescription`? | response |
| `status` | HTTP status line text (`HTTP/1.1 200 OK`) | response or propstat |
| `prop` | property elements | propstat, set, remove, LOCK response |
| `href` | URI or relative reference | response, locktoken, lockroot, etc. |
| `error` | precondition/postcondition elements | response, propstat, error body |
| `responsedescription` | text | multistatus, response, propstat |
| `location` | `href` | response (redirects) |

### Lock Elements

| Element | Contains | Used In |
|---------|----------|---------|
| `lockscope` | `exclusive` \| `shared` | lockinfo, activelock, lockentry |
| `locktype` | `write` | lockinfo, activelock, lockentry |
| `exclusive` | EMPTY | lockscope |
| `shared` | EMPTY | lockscope |
| `write` | EMPTY | locktype |
| `owner` | ANY (typically `href`) | lockinfo, activelock |
| `locktoken` | `href` | activelock |
| `lockroot` | `href` | activelock |
| `depth` | `"0"` \| `"1"` \| `"infinity"` | activelock |
| `timeout` | TimeType text | activelock |
| `activelock` | `lockscope`, `locktype`, `depth`, `owner`?, `timeout`?, `locktoken`?, `lockroot` | lockdiscovery |
| `lockentry` | `lockscope`, `locktype` | supportedlock |
| `lockdiscovery` | `activelock`* | DAV property |
| `supportedlock` | `lockentry`* | DAV property |

### Other Elements

| Element | Contains |
|---------|----------|
| `collection` | EMPTY (used in resourcetype) |

---

## 11. DAV Properties

All in `DAV:` namespace. Properties on all resources unless noted.

### 11.1 creationdate

- **Value:** ISO 8601 date-time (RFC 3339 format, e.g., `1997-12-01T17:42:21-08:00`)
- **Protected:** MAY be protected
- **COPY:** Re-initialised at destination
- **MOVE:** SHOULD be preserved
- **SHOULD** be defined on all DAV-compliant resources

### 11.2 displayname

- **Value:** Any text
- **Protected:** SHOULD NOT be protected
- **COPY/MOVE:** SHOULD be preserved
- **Notes:** For human display; not an identifier. Two resources can have same displayname.

### 11.3 getcontentlanguage

- **Value:** Language tag (e.g., `en-US`)
- **Protected:** SHOULD NOT be protected
- **MUST** be defined if resource returns `Content-Language` header on GET
- **COPY/MOVE:** SHOULD be preserved

### 11.4 getcontentlength

- **Value:** Integer (bytes)
- **Protected:** Yes (computed)
- **MUST** be defined if resource returns `Content-Length` on GET
- **COPY/MOVE:** Depends on destination content size

### 11.5 getcontenttype

- **Value:** Media type (e.g., `text/html`)
- **Protected:** Potentially (server may assign types)
- **MUST** be defined if resource returns `Content-Type` on GET
- **COPY/MOVE:** SHOULD be preserved

### 11.6 getetag

- **Value:** Entity tag (e.g., `"zzyzx"`)
- **Protected:** MUST be protected
- **MUST** be defined if resource returns `ETag` header
- **COPY/MOVE:** Depends on destination state
- **Strong ETags** preferred for authoring scenarios

### 11.7 getlastmodified

- **Value:** RFC 1123 date (e.g., `Mon, 12 Jan 1998 09:25:56 GMT`)
- **Protected:** SHOULD be protected
- **MUST** be defined if resource returns `Last-Modified` on GET
- **Notes:** Should reflect body changes only, not property changes

### 11.8 lockdiscovery

- **Value:** Zero or more `<activelock>` elements
- **Protected:** MUST be protected (changed via LOCK/UNLOCK, not PROPPATCH)
- **Notes:** If no locks but server supports locking → empty property. NOT lockable.

### 11.9 resourcetype

- **Value:** Child elements identifying resource types
- **Protected:** SHOULD be protected
- **MUST** be defined on all DAV-compliant resources
- **Collection:** `<D:resourcetype><D:collection/></D:resourcetype>`
- **Non-collection:** `<D:resourcetype/>` (empty)
- Extensible: other types can add child elements

### 11.10 supportedlock

- **Value:** Zero or more `<lockentry>` elements
- **Protected:** MUST be protected
- **Notes:** Lists supported lock scope/type combinations. NOT lockable.

### Summary Table

| Property | Protected | On GET resources | On all resources |
|----------|-----------|-----------------|------------------|
| `creationdate` | MAY | | SHOULD |
| `displayname` | SHOULD NOT | | SHOULD |
| `getcontentlanguage` | SHOULD NOT | If Content-Language returned | |
| `getcontentlength` | Yes | If Content-Length returned | |
| `getcontenttype` | Maybe | If Content-Type returned | |
| `getetag` | Yes | If ETag returned | |
| `getlastmodified` | SHOULD | If Last-Modified returned | |
| `lockdiscovery` | Yes | | If locking supported |
| `resourcetype` | SHOULD | | MUST |
| `supportedlock` | Yes | | If locking supported |

---

## 12. Precondition/Postcondition Codes

XML elements returned in `<error>` body for structured error reporting.

| Code Element | Used With | Meaning |
|-------------|-----------|---------|
| `lock-token-matches-request-uri` | 409 | UNLOCK token doesn't match Request-URI scope |
| `lock-token-submitted` | 423 | Lock token should have been submitted. Contains `<href>` of locked resource(s). |
| `no-conflicting-lock` | 423 | LOCK failed due to existing conflicting lock. MAY contain `<href>` of lock root. |
| `no-external-entities` | 403 | Server rejects XML with external entities |
| `preserved-live-properties` | 409 | MOVE/COPY can't maintain live property behaviour at destination |
| `propfind-finite-depth` | 403 | Server rejects infinite-depth PROPFIND |
| `cannot-modify-protected-property` | 403 | PROPPATCH tried to change protected property |

**Error response format:**

```xml
HTTP/1.1 423 Locked
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8"?>
<D:error xmlns:D="DAV:">
  <D:lock-token-submitted>
    <D:href>/locked/resource</D:href>
  </D:lock-token-submitted>
</D:error>
```

---

## 13. Compliance Classes

### Class 1 (Mandatory Base)
- MUST meet all MUST requirements in RFC 4918
- MUST return `DAV: 1` on OPTIONS
- Includes: PROPFIND, PROPPATCH, MKCOL, GET, HEAD, PUT, DELETE, COPY, MOVE, OPTIONS
- Includes: all properties, XML processing, Multi-Status responses

### Class 2 (Locking)
- MUST be Class 1 compliant
- MUST support: LOCK, UNLOCK methods
- MUST support: `DAV:supportedlock`, `DAV:lockdiscovery` properties
- MUST support: `Lock-Token` request/response header, `Timeout` response header
- SHOULD support: `Timeout` request header, `<owner>` element
- MUST return `DAV: 1, 2` on OPTIONS

### Class 3 (RFC 4918 Revisions)
- MUST be Class 1 compliant
- MAY be Class 2 compliant
- Advertises support for RFC 4918 (vs older RFC 2518)
- `DAV: 1, 3` (without locking) or `DAV: 1, 2, 3` (with locking)

---

## 14. General Rules

### XML Processing
- All XML MUST be well-formed and use namespaces correctly
- Malformed XML → 400 Bad Request
- MUST use XML parsers compliant with XML 1.0 and XML Namespaces
- Unexpected elements/attributes: MUST ignore for processing purposes
- Processing instructions: SHOULD ignore
- `Content-Type` SHOULD be `application/xml`; MUST accept `text/xml` and `application/xml`

### URL Handling
- All `<href>` values in a multistatus MUST use same format (all absolute or all relative)
- MUST NOT use dot-segments (`.` or `..`)
- Collection URLs SHOULD end with `/`
- Percent-encoding required in URIs (e.g., spaces → `%20`)

### Request Bodies
- If body present but not expected → 415 Unsupported Media Type
- Server MUST examine all requests for bodies

### ETags
- Strong ETags preferred for authoring
- Server SHOULD NOT change ETag if body unchanged
- ETags necessary alongside locks to avoid lost updates

### Authorization
- Auth checks MUST happen BEFORE conditional header checks
- Lock doesn't confer write privilege; normal access control still applies

### Error Bodies
- Structured error responses use `<error>` element containing precondition/postcondition codes
- SHOULD use these when defined preconditions are violated
- Custom conditions in custom XML namespaces are permitted

### Caching
- Responses to PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK MUST NOT be cached
- PROPFIND MAY be cached (with care — no cache validation for most properties)

### Security Considerations
- Reject XML with external entities (billion laughs, XXE attacks)
- Lock tokens should not be guessable (use UUIDs)
- Support HTTP authentication mechanisms (Basic over TLS, Digest, etc.)
- Don't rely on security through obscurity of locked resources
