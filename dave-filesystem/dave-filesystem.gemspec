Gem::Specification.new do |spec|
  spec.name          = "dave-filesystem"
  spec.version       = "0.1.0"
  spec.authors       = ["Dave"]
  spec.summary       = "Filesystem provider for Dave WebDAV server"
  spec.require_paths = ["lib"]
  spec.files         = Dir["lib/**/*.rb"]
  spec.required_ruby_version = ">= 3.2"

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov"
end
