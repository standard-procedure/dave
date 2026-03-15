Gem::Specification.new do |spec|
  spec.name          = "samba-dave"
  spec.version       = "0.1.0"
  spec.authors       = ["Dave"]
  spec.summary       = "SMB2 file server using Dave provider interfaces"
  spec.description   = "An SMB2 file server that shares pluggable provider interfaces with dave-server (WebDAV). " \
                        "One FileSystemProvider implementation serves both protocols."
  spec.require_paths = ["lib"]
  spec.files         = Dir["lib/**/*.rb"]
  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "dave-server"          # Shared interfaces: FileSystemInterface, SecurityInterface, Resource, Principal
  spec.add_dependency "rubyntlm", "~> 0.6"  # NTLM Type 1/2/3 message handling
  spec.add_dependency "bindata", "~> 2.5"   # Binary struct definitions for SMB2 wire format

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov"
end
