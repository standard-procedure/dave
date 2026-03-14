# Dave — Implementation Plan

> A WebDAV server implemented as a Ruby/Rack gem mono-repo.

---

## Table of Contents

1. [Mono-Repo Structure](#1-mono-repo-structure)
2. [Pluggable FileSystem Provider Interface](#2-pluggable-filesystem-provider-interface)
3. [Pluggable Security Provider Interface](#3-pluggable-security-provider-interface)
4. [Embeddability](#4-embeddability)
5. [Multi-Agent TDD Workflow](#5-multi-agent-tdd-workflow)
6. [Development Phases](#6-development-phases)

---

## 1. Mono-Repo Structure

Dave is a mono-repo containing three Ruby gems that work together but can be used independently.

```
dave/
├── AGENTS.md                    # LLM agent entry point
├── CLAUDE.md                    # Symlink → AGENTS.md
├── README.md                    # Human-friendly overview
├── Gemfile                      # Root Gemfile for development (references all gems)
├── docs/
│   ├── WEBDAV-SPEC.md           # WebDAV RFC 4918 reference
│   ├── IMPLEMENTATION-PLAN.md   # This file
│   └── ARCHITECTURE.md          # Architecture decisions
├── dave-server/
│   ├── dave-server.gemspec
│   ├── Gemfile
│   ├── README.md
│   ├── lib/
│   │   └── dave/
│   │       └── server.rb        # Dave::Server (Rack app)
│   ├── spec/
│   └── docs/
├── dave-filesystem/
│   ├── dave-filesystem.gemspec
│   ├── Gemfile
│   ├── README.md
│   ├── lib/
│   │   └── dave/
│   │       └── file_system_provider.rb
│   ├── spec/
│   └── docs/
└── dave-security/
    ├── dave-security.gemspec
    ├── Gemfile
    ├── README.md
    ├── lib/
    │   └── dave/
    │       └── security_configuration.rb
    ├── spec/
    └── docs/
```

### Gem Details

| Gem | Module | Responsibility |
|-----|--------|---------------|
| `dave-server` | `Dave::Server` | Core Rack application. Parses WebDAV requests, routes to providers, generates XML responses. |
| `dave-filesystem` | `Dave::FileSystemProvider` | Default filesystem backend. Wraps local disk. Implements provider interface. |
| `dave-security` | `Dave::SecurityConfiguration` | Default auth/authz. YAML-based user config with bcrypt passwords and path ACLs. |

### Dependencies

```
dave-server depends on:
  - rack (>= 2.0)
  - nokogiri (XML parsing/generation)
  - dave-filesystem (default, optional — can use any provider)
  - dave-security (default, optional — can use any provider)

dave-filesystem depends on:
  - (no external deps beyond Ruby stdlib)

dave-security depends on:
  - bcrypt
  - yaml (stdlib)
```

### Development Dependencies (all gems)

```
rspec (~> 3.0)
rack-test
webmock (for integration tests)
simplecov
rubocop
```

---

## 2. Pluggable FileSystem Provider Interface

### Interface Contract

Any filesystem provider MUST implement the following methods. The provider is instantiated once per server configuration and receives path strings relative to the DAV root.

```ruby
module Dave
  module FileSystemProvider
    # All paths are strings relative to the DAV root (e.g., "/docs/file.txt")
    # Paths for collections always end with "/"

    # === Resource Query ===

    # Returns true if a resource exists at the given path
    # @param path [String]
    # @return [Boolean]
    def exists?(path)

    # Returns true if the resource at path is a collection (directory)
    # @param path [String]
    # @return [Boolean]
    def collection?(path)

    # Returns metadata hash for the resource
    # @param path [String]
    # @return [Hash] with keys:
    #   :content_type [String] MIME type (nil for collections)
    #   :content_length [Integer] size in bytes (nil for collections)
    #   :etag [String] entity tag (strong)
    #   :last_modified [Time]
    #   :creation_date [Time]
    #   :display_name [String]
    # @raise [Dave::NotFoundError] if resource doesn't exist
    def stat(path)

    # Lists direct children of a collection
    # @param path [String] must be a collection path
    # @return [Array<String>] child names (NOT full paths)
    # @raise [Dave::NotFoundError] if collection doesn't exist
    # @raise [Dave::NotACollectionError] if path is not a collection
    def children(path)

    # === Read ===

    # Returns the content of a resource as an IO-like object (responds to #read, #each)
    # @param path [String]
    # @return [IO] readable stream
    # @raise [Dave::NotFoundError]
    def read(path)

    # === Write ===

    # Writes content to a resource, creating it if it doesn't exist
    # @param path [String]
    # @param content [IO] readable stream
    # @param content_type [String, nil] MIME type
    # @return [String] etag of the written resource
    # @raise [Dave::NotFoundError] if parent collection doesn't exist
    def write(path, content, content_type: nil)

    # Creates a new collection
    # @param path [String]
    # @raise [Dave::AlreadyExistsError] if path already mapped
    # @raise [Dave::NotFoundError] if parent collection doesn't exist
    def make_collection(path)

    # === Delete ===

    # Deletes a resource or collection (and all contents)
    # @param path [String]
    # @return [Array<String>] list of paths that could NOT be deleted (empty on full success)
    # @raise [Dave::NotFoundError]
    def delete(path)

    # === Copy/Move ===

    # Copies a resource or collection from source to destination
    # @param source [String]
    # @param destination [String]
    # @param depth [Symbol] :zero or :infinity
    # @param overwrite [Boolean]
    # @return [Symbol] :created or :no_content
    # @raise [Dave::NotFoundError] if source doesn't exist
    # @raise [Dave::AlreadyExistsError] if !overwrite and destination exists
    # @raise [Dave::NotFoundError] if destination parent doesn't exist
    def copy(source, destination, depth: :infinity, overwrite: true)

    # Moves a resource or collection from source to destination
    # @param source [String]
    # @param destination [String]
    # @param overwrite [Boolean]
    # @return [Symbol] :created or :no_content
    # @raise [Dave::NotFoundError] if source doesn't exist
    # @raise [Dave::AlreadyExistsError] if !overwrite and destination exists
    # @raise [Dave::NotFoundError] if destination parent doesn't exist
    def move(source, destination, overwrite: true)

    # === Properties ===

    # Returns dead properties for a resource
    # @param path [String]
    # @return [Hash<String, String>] property name (Clark notation "{ns}local") => XML value
    def get_properties(path)

    # Sets dead properties on a resource
    # @param path [String]
    # @param properties [Hash<String, String>] property name => XML value
    # @raise [Dave::NotFoundError]
    def set_properties(path, properties)

    # Removes dead properties from a resource
    # @param path [String]
    # @param property_names [Array<String>] property names in Clark notation
    # @raise [Dave::NotFoundError]
    def remove_properties(path, property_names)

    # Returns all property names (both live and dead) for a resource
    # @param path [String]
    # @return [Array<String>] property names in Clark notation
    def property_names(path)
  end
end
```

### Custom Errors

```ruby
module Dave
  class Error < StandardError; end
  class NotFoundError < Error; end
  class AlreadyExistsError < Error; end
  class NotACollectionError < Error; end
  class LockedError < Error; end
  class InsufficientStorageError < Error; end
end
```

### Compliance Test Suite

Implementers include `Dave::FileSystemProvider::ComplianceTests` in their RSpec suite:

```ruby
# In the implementer's spec file:
RSpec.describe MyCustomProvider do
  include Dave::FileSystemProvider::ComplianceTests

  # Must define a `provider` let that returns an instance of the provider
  # configured with an empty, writable storage root
  let(:provider) { MyCustomProvider.new(root: Dir.mktmpdir) }

  # The compliance suite runs all tests automatically
end
```

**Compliance tests cover:**

1. **Existence** — `exists?` returns false for missing, true for existing
2. **Collections** — `make_collection`, `collection?`, `children`
3. **Read/Write** — `write` creates resource, `read` returns content, `stat` returns metadata
4. **Overwrite** — `write` to existing path updates content and etag
5. **Delete** — removes resource, returns empty array; collection deletes recursively
6. **Copy** — non-collection, collection with depth 0 and infinity, overwrite true/false
7. **Move** — non-collection, collection, overwrite true/false
8. **Properties** — get/set/remove dead properties, property_names
9. **Error cases** — NotFoundError for missing parents, AlreadyExistsError for existing paths
10. **ETags** — etag changes on write, is consistent across stat calls
11. **Nested collections** — deep hierarchies work correctly

---

## 3. Pluggable Security Provider Interface

### Interface Contract

```ruby
module Dave
  module SecurityProvider
    # Authenticates a request. Returns a principal or nil.
    # @param request [Rack::Request]
    # @return [Dave::Principal, nil] authenticated principal, or nil if not authenticated
    def authenticate(request)

    # Returns the authentication challenge to send in WWW-Authenticate header
    # @return [String] e.g., 'Basic realm="WebDAV"'
    def challenge

    # Checks if the principal is authorised for the given operation on path
    # @param principal [Dave::Principal]
    # @param path [String] resource path
    # @param operation [Symbol] :read or :write
    # @return [Boolean]
    def authorised?(principal, path, operation)
  end

  # Represents an authenticated user
  class Principal
    attr_reader :name, :display_name

    def initialize(name:, display_name: nil)
      @name = name
      @display_name = display_name || name
    end
  end
end
```

### Operations

| Operation | Methods |
|-----------|---------|
| `:read` | GET, HEAD, PROPFIND, OPTIONS |
| `:write` | PUT, DELETE, MKCOL, PROPPATCH, COPY, MOVE, LOCK, UNLOCK |

### Default Provider: `Dave::SecurityConfiguration`

Reads a YAML configuration file:

```yaml
# dave-security.yml
realm: "Dave WebDAV"
authentication: basic  # basic | digest

users:
  alice:
    password: "$2a$12$..."  # bcrypt hash
    display_name: "Alice Smith"
    access:
      - path: "/"
        permission: read_write
      - path: "/public/"
        permission: read_write

  bob:
    password: "$2a$12$..."
    display_name: "Bob Jones"
    access:
      - path: "/"
        permission: read
      - path: "/bob/"
        permission: read_write

  guest:
    password: "$2a$12$..."
    access:
      - path: "/public/"
        permission: read

anonymous:
  enabled: false
  access:
    - path: "/public/"
      permission: read
```

**Path matching rules:**
- Paths are matched as prefixes with `/` boundaries
- More specific paths override less specific ones
- No match → access denied

### Compliance Test Suite

```ruby
RSpec.describe MySecurityProvider do
  include Dave::SecurityProvider::ComplianceTests

  # Must define these lets:
  let(:provider) { MySecurityProvider.new(config) }
  let(:read_only_user) { "reader" }          # username with read-only access to /
  let(:read_write_user) { "writer" }         # username with read-write access to /
  let(:restricted_user) { "restricted" }     # username with NO access to /secret/
  let(:read_only_password) { "pass1" }
  let(:read_write_password) { "pass2" }
  let(:restricted_password) { "pass3" }
end
```

**Compliance tests cover:**

1. **Authentication** — valid credentials return Principal, invalid return nil
2. **Challenge** — returns valid WWW-Authenticate header value
3. **Read authorisation** — read-only user can read, cannot write
4. **Write authorisation** — read-write user can read and write
5. **Path-based access** — access rules are path-scoped
6. **Restricted paths** — user without access to a path is denied

---

## 4. Embeddability

### Rack Application

`Dave::Server` is a standard Rack application (responds to `#call(env)`).

```ruby
# Standalone
server = Dave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/webdav"),
  security: Dave::SecurityConfiguration.new(config_path: "/etc/dave/security.yml"),
  prefix: "/dav"  # optional URL prefix
)

# As Rack app
run server

# In config.ru
map "/dav" do
  run Dave::Server.new(
    filesystem: Dave::FileSystemProvider.new(root: "/var/webdav")
  )
end
```

### Rails Mount

```ruby
# config/routes.rb
Rails.application.routes.draw do
  mount Dave::Server.new(
    filesystem: Dave::FileSystemProvider.new(root: Rails.root.join("storage/webdav")),
    security: Dave::SecurityConfiguration.new(config_path: Rails.root.join("config/dave-security.yml"))
  ) => "/dav"
end
```

### Hanami Mount

```ruby
# config/routes.rb
mount Dave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/webdav")
), at: "/dav"
```

### Configuration Options

```ruby
Dave::Server.new(
  filesystem:,          # Required: object implementing FileSystemProvider interface
  security: nil,        # Optional: object implementing SecurityProvider interface (nil = no auth)
  prefix: "",           # Optional: URL prefix to strip from incoming requests
  lockmanager: nil,     # Optional: custom lock manager (nil = in-memory default)
  logger: nil,          # Optional: Logger instance
  compliance_class: 2,  # 1 = no locking, 2 = with locking, 3 = RFC 4918 compliance
)
```

### Design Principles

1. **No global state** — all state scoped to the server instance
2. **Thread-safe** — providers must be thread-safe; lock manager uses mutex
3. **No framework dependencies** — pure Rack, no Rails/Hanami/Sinatra required
4. **Provider injection** — filesystem and security injected at construction time
5. **Sensible defaults** — works out of the box with local filesystem and no auth

---

## 5. Multi-Agent TDD Workflow

### Tooling: Claude Code CLI + Plugins

All coding agents are invoked via the **Claude Code CLI** (not as OpenClaw subagents) so they have access to the installed plugins:

```bash
claude --print --permission-mode bypassPermissions --model <model> -p "<task prompt>"
```

**Why CLI, not subagents:** Claude Code CLI loads plugins from `~/.claude/plugins/` which provide enforced TDD workflow, subagent dispatch, and automated code review. These plugins are not available to OpenClaw-spawned subagents.

#### Installed Plugins

**Superpowers Plugin** (`~/.claude/plugins/cache/claude-plugins-official/superpowers/5.0.2/`)

| Skill | Purpose | When Used |
|-------|---------|-----------|
| `test-driven-development` | Enforces strict Red/Green/Refactor — no production code without a failing test first | **MANDATORY** for all developer agents |
| `subagent-driven-development` | Dispatch a fresh subagent per task with two-stage review (spec compliance → code quality) | **PRIMARY workflow** for implementation tasks |
| `writing-plans` | Structured planning output | Planner agents |
| `dispatching-parallel-agents` | Run multiple agents concurrently | Parallel story execution within a phase |
| `requesting-code-review` | Prepare code for review | Developer agents after completing a story |
| `receiving-code-review` | Process review feedback | Developer agents responding to review |
| `finishing-a-development-branch` | Branch cleanup, squash, PR preparation | End of each story/feature |
| `verification-before-completion` | Final checks before marking complete | All agents before finishing |

**Code Review Plugin** — `/code-review` command

Launches 4 parallel review agents:
1. CLAUDE.md compliance check (x2 agents for coverage)
2. Bug scan
3. Git history context review

Each issue scored 0-100; only issues ≥80 confidence reported. Posts PR comment automatically.

### Agent Roles

| Role | Responsibility | Invocation |
|------|---------------|------------|
| **Planner** | Breaks phase into stories/tasks, writes specs | `claude --print --permission-mode bypassPermissions --model sonnet -p "..."` |
| **Developer** | Implements features via strict TDD (Red/Green/Refactor) | `claude --print --permission-mode bypassPermissions --model opus -p "..."` |
| **Tester** | Writes integration/acceptance tests, runs compliance suites | `claude --print --permission-mode bypassPermissions --model sonnet -p "..."` |
| **Reviewer** | Automated code review via `/code-review` command | `claude --print --permission-mode bypassPermissions -p "/code-review"` |

### Primary Workflow: Subagent-Driven Development

The `subagent-driven-development` plugin skill is the **primary workflow** for all implementation tasks. It dispatches a fresh subagent per task and performs two-stage review:

1. **Stage 1: Spec compliance review** — does the implementation satisfy the task requirements and RFC 4918?
2. **Stage 2: Code quality review** — Ruby idioms, SOLID principles, thread safety, test coverage

This replaces ad-hoc agent spawning. The orchestrating agent uses the plugin's dispatch mechanism rather than manually coordinating handoffs.

### Mandatory: Test-Driven Development

All developer agents **MUST** follow the `test-driven-development` plugin skill strictly:

1. **Red** — write a failing test first. No production code until you have a red test.
2. **Green** — write the minimum code to make the test pass.
3. **Refactor** — clean up while keeping green.
4. Commit after each green step.

The plugin enforces this. If a developer agent tries to write production code without a failing test, the plugin will block it.

### Workflow Per Story

```
┌─────────┐     ┌───────────────────────────┐     ┌──────────────┐
│ Planner  │────▶│ Developer (via subagent-  │────▶│ /code-review │
│          │     │ driven-development)       │     │              │
│ • Story  │     │                           │     │ • 4 parallel │
│ • Tasks  │     │ • test-driven-development │     │   reviewers  │
│ • Specs  │     │ • Two-stage review:       │     │ • Score ≥80  │
│          │     │   1. Spec compliance      │     │ • PR comment │
│          │     │   2. Code quality         │     │              │
└─────────┘     └───────────────────────────┘     └──────────────┘
```

### Step-by-Step Process

#### 1. Planner Agent (per phase)

Invoked via: `claude --print --permission-mode bypassPermissions --model sonnet`

Uses the `writing-plans` plugin skill.

- Reads `IMPLEMENTATION-PLAN.md` and `WEBDAV-SPEC.md`
- Creates task breakdown in `docs/phases/phase-N/TASKS.md`
- Writes RSpec describe/context stubs (empty `it` blocks with descriptions)
- Defines acceptance criteria referencing specific RFC section numbers
- Outputs: task list, spec skeleton files

#### 2. Developer Agent (per story)

Invoked via: `claude --print --permission-mode bypassPermissions --model opus`

Uses the `subagent-driven-development` and `test-driven-development` plugin skills (mandatory).

- Dispatches via `subagent-driven-development` which handles task scoping and review
- Reads task from Planner output
- **Red:** Writes failing spec (or fills in Planner's stub)
- **Green:** Writes minimal code to pass
- **Refactor:** Cleans up while keeping green
- Commits after each green step
- Two-stage review runs automatically via the plugin
- Uses `finishing-a-development-branch` skill to prepare the branch
- Uses `verification-before-completion` skill before marking done
- Outputs: implementation code, passing unit specs, clean branch

#### 3. Tester Agent (per story or batch)

Invoked via: `claude --print --permission-mode bypassPermissions --model sonnet`

- Writes integration tests using Rack::Test
- Runs compliance test suites
- Tests against real WebDAV clients (litmus test suite) if available
- Verifies Multi-Status XML responses match spec
- Outputs: integration specs, compliance report

#### 4. Code Review (per PR/branch)

Invoked via: `claude --print --permission-mode bypassPermissions -p "/code-review"`

This is run **after each story branch is complete**, before merge:

- Launches 4 parallel review agents automatically
- CLAUDE.md compliance (x2): checks code follows project conventions in AGENTS.md/CLAUDE.md
- Bug scan: looks for logic errors, edge cases, security issues
- Git history context: reviews commit messages and change patterns
- Each issue scored 0-100 confidence; only issues ≥80 are reported
- Posts summary as PR comment (or to stdout if no PR)
- **Gate:** Resolve all ≥80 confidence issues before merging

### Parallel Execution

For stories within a phase that have no dependencies, use the `dispatching-parallel-agents` plugin skill to run multiple developer agents concurrently. For example, in Phase 1:

- Story "GET handler" and Story "MKCOL handler" can run in parallel
- Story "DELETE handler" depends on file creation (PUT), so it runs after

### Handoff Protocol

Each agent produces a **summary file** at completion:

```
docs/phases/phase-N/stories/story-M/
  TASK.md          # Planner output
  DEVELOPER.md     # Developer summary (what was done, decisions made)
  TESTER.md        # Test results and coverage
  REVIEW.md        # /code-review output (issues, scores, resolution)
```

### Proving Spec Compliance

For each WebDAV method, the test suite includes:

1. **Happy path** — standard successful operation
2. **Status codes** — every status code listed in the method's spec section
3. **Headers** — correct request/response headers
4. **XML bodies** — well-formed, namespace-correct request and response XML
5. **Error conditions** — precondition codes, lock conflicts, missing parents
6. **Depth handling** — 0, 1, infinity where applicable
7. **Collection semantics** — namespace consistency maintained

**RFC compliance matrix** maintained in `docs/COMPLIANCE-MATRIX.md`:

```markdown
| RFC Section | Feature | Status | Test File |
|------------|---------|--------|-----------|
| 9.1 | PROPFIND | ✅ | spec/integration/propfind_spec.rb |
| 9.2 | PROPPATCH | ✅ | spec/integration/proppatch_spec.rb |
| 9.3 | MKCOL | 🚧 | spec/integration/mkcol_spec.rb |
...
```

---

## 6. Development Phases

### Phase 0: Project Skeleton (Foundation)

**Goal:** Bootable gem structure with CI, testing infrastructure, and empty Rack app.

**Tasks:**
1. Create gemspec files for all three gems
2. Set up RSpec configuration in each gem
3. Create `Dave::Server` as a Rack app that returns 200 OK
4. Create placeholder provider interfaces (modules with method stubs)
5. Set up root Gemfile referencing all gems via path
6. Create `.rspec`, `.rubocop.yml`, `Rakefile`
7. Implement `Dave::Server#call(env)` with basic method routing
8. OPTIONS method returns `DAV: 1` header and allowed methods
9. Write `AGENTS.md`, `CLAUDE.md`, `README.md`, `ARCHITECTURE.md`

**Exit criteria:** `bundle exec rspec` runs in each gem directory. OPTIONS returns DAV header.

---

### Phase 1: Core Read/Write (GET, PUT, DELETE, MKCOL, HEAD)

**Goal:** Basic file and folder operations via WebDAV.

**Tasks:**

#### FileSystem Provider
1. Implement `Dave::FileSystemProvider` with local disk backend
2. Implement compliance test suite (`Dave::FileSystemProvider::ComplianceTests`)
3. Test: create/read/update/delete files and folders

#### Server Methods
4. **GET** — serve file content with correct Content-Type, Content-Length, ETag, Last-Modified
5. **HEAD** — same headers as GET, no body
6. **PUT** — create/overwrite file, return 201/204, handle missing parent (409)
7. **DELETE** — delete resource/collection, recursive for collections, 207 on partial failure
8. **MKCOL** — create collection, handle all error cases (405, 409, 415)

#### Infrastructure
9. Request parsing: extract path, headers, body
10. Response generation: status codes, standard headers
11. Error handling: map Dave errors to HTTP status codes
12. Collection trailing-slash handling

**Exit criteria:** Can create folders, upload files, download files, and delete both via any HTTP client (curl).

**Estimated agent-hours:** 4-6 stories, ~2-3 developer agent runs

---

### Phase 2: Properties (PROPFIND, PROPPATCH)

**Goal:** Full property support — live and dead properties, XML request/response marshalling.

**Tasks:**

#### XML Infrastructure
1. XML request parser (Nokogiri-based): parse propfind, propertyupdate bodies
2. XML response builder: generate multistatus, response, propstat elements
3. Namespace handling: DAV: namespace, custom namespaces

#### PROPFIND
4. `<prop>` — return named properties
5. `<allprop>` — return all dead + RFC 4918 live properties
6. `<allprop>` + `<include>` — allprop plus additional named properties
7. `<propname>` — return all property names
8. Empty body → allprop
9. Depth: 0, 1, infinity handling
10. Multi-Status response with propstat grouping

#### PROPPATCH
11. `<set>` — set dead properties
12. `<remove>` — remove dead properties
13. Atomic: all-or-nothing semantics
14. Protected property handling (403 + `cannot-modify-protected-property`)

#### Live Properties
15. Implement all 10 DAV: properties from section 15
16. Computed properties: getcontentlength, getetag, getlastmodified
17. resourcetype: collection vs non-collection

**Exit criteria:** macOS Finder or Windows Explorer can browse the WebDAV server and see file metadata.

**Estimated agent-hours:** 6-8 stories, ~3-4 developer agent runs

---

### Phase 3: Namespace Operations (COPY, MOVE)

**Goal:** Copy and move resources and collections.

**Tasks:**

1. **COPY non-collection** — duplicate resource at destination
2. **COPY collection** — Depth 0 (just collection) and Depth infinity (recursive)
3. **MOVE non-collection** — COPY + DELETE source
4. **MOVE collection** — recursive move
5. Destination header parsing and validation
6. Overwrite header handling (T/F, default T)
7. Cross-collection operations
8. Property preservation (dead → MUST copy, live → SHOULD behave identically)
9. Error handling: missing intermediates (409), locked destinations (423), 207 for partial failures
10. Namespace consistency enforcement

**Exit criteria:** Files and folders can be copied and moved. Overwrite behaviour is correct.

**Estimated agent-hours:** 4-5 stories, ~2-3 developer agent runs

---

### Phase 4: Locking (LOCK, UNLOCK)

**Goal:** Full write-lock support (Class 2 compliance).

**Tasks:**

#### Lock Manager
1. In-memory lock manager with mutex for thread safety
2. Lock storage: lock token → lock info (scope, type, depth, owner, timeout, root)
3. Lock conflict detection (exclusive vs shared compatibility table)
4. Lock timeout management (background reaper or lazy expiry)
5. Lock token generation (UUID URN format)

#### LOCK Method
6. Create exclusive write lock on resource
7. Create shared write lock on resource
8. Depth 0 and depth infinity locks
9. Lock on unmapped URL (create empty resource)
10. Lock refresh via If header
11. Lock response body (lockdiscovery XML)
12. Lock-Token response header

#### UNLOCK Method
13. Remove lock by token
14. Validate token matches request-URI scope
15. All-or-nothing: if any resource can't be unlocked, fail entirely

#### Lock Enforcement
16. If header parsing (tagged lists, no-tag lists, Not, ETags)
17. Lock token submission validation on write operations
18. All write methods check lock state before proceeding
19. Collection lock: adding/removing members requires lock token

#### Properties
20. `DAV:lockdiscovery` — list active locks
21. `DAV:supportedlock` — list supported lock types

**Exit criteria:** Class 2 compliance. Lock/unlock works. Locked resources reject unauthorized writes.

**Estimated agent-hours:** 8-10 stories, ~4-5 developer agent runs

---

### Phase 5: Authentication & Authorisation

**Goal:** Pluggable security with a working default provider.

**Tasks:**

#### Security Provider
1. Implement `Dave::SecurityConfiguration` with YAML config parsing
2. bcrypt password verification
3. HTTP Basic authentication
4. Path-based authorisation (read vs read-write)
5. Anonymous access support (configurable)
6. Compliance test suite (`Dave::SecurityProvider::ComplianceTests`)

#### Server Integration
7. Authentication middleware/hook in request pipeline
8. 401 Unauthorized with WWW-Authenticate header when auth required
9. 403 Forbidden when authenticated but not authorised
10. Auth check before all conditional headers (per spec)
11. Lock creator identity verification

**Exit criteria:** Users authenticate, access is path-scoped, unauthorized requests are rejected.

**Estimated agent-hours:** 4-5 stories, ~2-3 developer agent runs

---

### Phase 6: Compliance & Hardening

**Goal:** Pass litmus test suite, handle edge cases, production-ready.

**Tasks:**

1. Run [litmus WebDAV test suite](http://www.webdav.org/neon/litmus/) and fix failures
2. Test with real clients: macOS Finder, Windows Explorer, Cyberduck, rclone, cadaver
3. Large file handling (streaming, not loading into memory)
4. Character encoding: UTF-8 paths, internationalised property values
5. Correct ETag handling (strong ETags, If-Match, If-None-Match)
6. XML security: reject external entities, limit entity expansion (XXE prevention)
7. Error response bodies with precondition/postcondition codes
8. Performance: streaming responses for large PROPFIND results
9. Logging: structured request/response logging
10. Thread safety audit
11. Complete RFC compliance matrix

**Exit criteria:** Litmus test suite passes. Works with major WebDAV clients. No known spec violations.

**Estimated agent-hours:** 6-8 stories, ~3-4 developer agent runs

---

### Phase Summary

| Phase | Focus | Class | Key Deliverable |
|-------|-------|-------|----------------|
| 0 | Skeleton | — | Bootable empty Rack app |
| 1 | Read/Write | Partial 1 | GET/PUT/DELETE/MKCOL/HEAD |
| 2 | Properties | Partial 1 | PROPFIND/PROPPATCH with full XML |
| 3 | Namespace | Full 1 | COPY/MOVE with all edge cases |
| 4 | Locking | Full 2 | LOCK/UNLOCK, If header, lock enforcement |
| 5 | Security | Full 2 | Auth/authz with pluggable provider |
| 6 | Compliance | Full 3 | Litmus passing, real-client tested |

**Total estimated effort:** 32-42 stories across 6 phases, ~16-22 developer agent runs.

---

## Appendix: Technology Choices

| Decision | Choice | Rationale |
|----------|--------|-----------|
| XML parsing | Nokogiri | Industry standard Ruby XML library; handles namespaces correctly |
| Password hashing | bcrypt | Standard for password storage; widely understood |
| UUID generation | SecureRandom.uuid | Ruby stdlib; sufficient for lock tokens |
| HTTP framework | Rack | Universal Ruby HTTP interface; works everywhere |
| Testing | RSpec + Rack::Test | Ruby standard; Rack::Test for integration tests |
| Config format | YAML | Ruby-native, human-readable, widely used |
| Lock storage | In-memory (default) | Simple, fast; can be replaced for distributed setups |
