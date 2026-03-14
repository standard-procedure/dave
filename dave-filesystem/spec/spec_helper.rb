require "simplecov"
SimpleCov.start

require "dave/file_system_provider"

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
