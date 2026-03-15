Gem::Specification.new do |spec|
  spec.name          = "dave-security"
  spec.version       = "0.1.0"
  spec.authors       = ["Dave"]
  spec.summary       = "Security configuration for Dave WebDAV server"
  spec.require_paths = ["lib"]
  spec.files         = Dir["lib/**/*.rb"]
  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "bcrypt"

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov"
end
