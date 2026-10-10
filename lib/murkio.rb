# frozen_string_literal: true

# Murkio identity for Ruby backends.
#
#   murkio = Murkio::Client.new            # reads MURKIO_PUBLISHABLE_KEY
#   use Murkio::Rack, client: murkio, required: true, sign_in_url: "/login"
#
# See Murkio::Client for the verification and the page helpers, and
# Murkio::Rack for the middleware.
module Murkio
end

require_relative "murkio/version"
require_relative "murkio/cdn"
require_relative "murkio/client"
require_relative "murkio/rack"
