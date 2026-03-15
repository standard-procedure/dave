require "simplecov"
SimpleCov.start

# Add dave-server to the load path so Dave::Principal is available before
# dave/security_configuration is required, preventing the constant-redefinition warning.
$LOAD_PATH.unshift File.expand_path("../../dave-server/lib", __dir__)
require "dave/principal"

require "dave/security_configuration"

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
