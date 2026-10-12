# frozen_string_literal: true

require_relative "lib/murkio/version"

Gem::Specification.new do |spec|
  spec.name = "murkio"
  spec.version = Murkio::VERSION
  spec.summary = "Murkio identity for Ruby backends"
  spec.description = "Verifies the session of each request (Rack, Rails, Sinatra) and writes the Murkio login components into server-rendered pages."
  spec.authors = ["Murkio"]
  spec.homepage = "https://github.com/ViitoJooj/murkio-ruby"
  spec.license = "Nonstandard"
  spec.required_ruby_version = ">= 3.1"
  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"
end
