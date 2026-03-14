require "simplecov"
SimpleCov.start

require "dave/security_configuration"

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
