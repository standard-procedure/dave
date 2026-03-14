Gem::Specification.new do |spec|
  spec.name          = "dave-server"
  spec.version       = "0.1.0"
  spec.authors       = ["Dave"]
  spec.summary       = "WebDAV server as a Rack application"
  spec.require_paths = ["lib"]
  spec.files         = Dir["lib/**/*.rb"]
  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "rack", ">= 2.0"
  spec.add_dependency "nokogiri"

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rack-test"
  spec.add_development_dependency "simplecov"
end
