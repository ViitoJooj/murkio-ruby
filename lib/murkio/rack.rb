# frozen_string_literal: true

module Murkio
  # Rack middleware (Rails, Sinatra, Hanami, plain Rack). The AuthResult goes
  # in env["murkio"]:
  #
  #   use Murkio::Rack                                           # optional auth
  #   use Murkio::Rack, required: true, sign_in_url: "/login"    # protect everything below
  #
  #   auth = Murkio::Rack.get(env)    # .session, .user, .reason
  #
  # Options: client (a Murkio::Client; default: one from the environment),
  # required, roles, sign_in_url, handshake, load_user and check_revocation
  # (see Murkio::Client#protect).
  class Rack
    ENV_KEY = "murkio"

    def self.get(env)
      env[ENV_KEY] || AuthResult.new(reason: "missing", signed_in_hint: false)
    end

    # The request fields Murkio::Client#protect needs, from a Rack env.
    def self.request(env)
      headers = {}
      env.each do |name, value|
        headers[name[5..].tr("_", "-").downcase] = value if name.is_a?(String) && name.start_with?("HTTP_") && value.is_a?(String)
      end
      query = env["QUERY_STRING"].to_s
      path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      path = "/" if path.empty?
      {
        method: env["REQUEST_METHOD"] || "GET",
        scheme: env["rack.url_scheme"] || "http",
        host: headers["host"] || env["SERVER_NAME"] || "localhost",
        path: query.empty? ? path : "#{path}?#{query}",
        headers: headers,
        cookies: parse_cookies(headers["cookie"])
      }
    end

    # Parses a Cookie header (the first value of a repeated name wins).
    def self.parse_cookies(header)
      header.to_s.split(";").each_with_object({}) do |part, cookies|
        name, value = part.strip.split("=", 2)
        next if name.nil? || name.empty? || value.nil? || value.empty? || cookies.key?(name)

        cookies[name] = URI.decode_www_form_component(value)
      rescue ArgumentError
        cookies[name] = value
      end
    end

    def initialize(app, client: nil, **options)
      @app = app
      @client = client || Client.new
      @options = options
    end

    def call(env)
      result, response = @client.protect(**self.class.request(env), **@options)
      env[ENV_KEY] = result
      return @app.call(env) unless response

      [response.status, response.headers, [response.body]]
    end
  end
end
