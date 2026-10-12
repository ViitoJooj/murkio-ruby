# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# What the pipeline runs. The gem itself has no runtime dependency, and the
# tests use the minitest that comes with Ruby.
group :development do
  gem "bundler-audit", "0.9.3", require: false
  gem "rubocop", "1.92.0", require: false
  gem "rubocop-performance", "1.27.0", require: false
end
