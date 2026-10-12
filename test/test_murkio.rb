# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "openssl"
require "murkio"

KEY = "pk_ruby_test"
VECTORS = JSON.parse(File.read(File.expand_path("../spec/server/vectors.json", __dir__)))

def b64(value)
  [value].pack("m0").tr("+/", "-_").delete("=")
end

# A fake identity API: real Ed25519 keys, no network.
class FakeApi
  attr_reader :calls, :revoked

  def initialize(jwks: nil, application: "app-1", issuer: "enterprise-auth")
    @private = OpenSSL::PKey.generate_key("ED25519")
    public_raw = @private.public_to_der.byteslice(-32, 32)
    @jwks = jwks || { "keys" => [{ "kty" => "OKP", "crv" => "Ed25519", "kid" => "k1", "alg" => "EdDSA", "x" => b64(public_raw) }] }
    @application = application
    @issuer = issuer
    @calls = []
    @revoked = {}
  end

  def call(method, url, headers, body)
    path = URI.parse(url).path
    @calls << "#{method} #{path}"
    case path
    when "/v1/client"
      return [401, JSON.generate(details: [{ code: "bss-01" }])] unless headers["Authorization"] == "Bearer #{KEY}"

      document = { note: "</script><b>&\u2028" }
      [200, JSON.generate(data: { application_id: @application, issuer: @issuer, jwks_url: "/jwks.json", config: {}, canvas: { version: 0, document: document } })]
    when "/jwks.json" then [200, JSON.generate(@jwks)]
    when "/v1/me"
      [200,
       JSON.generate(data: { id: "user-1", session_id: "session-1", email: "ana@example.com", email_verified: true, roles: ["user"], mfa_enabled: false,
                             created_at: "2026-10-10T00:00:00Z" })]
    when "/v1/sessions/verify"
      [200, JSON.generate(data: { active: !@revoked[JSON.parse(body)["access_token"]] })]
    else [404, "{}"]
    end
  end

  def token(kid: "k1", **claims)
    payload = { iss: @issuer, sub: "user-1", aud: @application, aid: @application, sid: "session-1", roles: ["user"],
                iat: Time.now.to_i, exp: Time.now.to_i + 900, jti: "j1" }.merge(claims)
    signing = "#{b64(JSON.generate(alg: 'EdDSA', kid: kid))}.#{b64(JSON.generate(payload))}"
    "#{signing}.#{b64(@private.sign(nil, signing))}"
  end

  def client(**options)
    Murkio::Client.new(publishable_key: KEY, api_url: "https://api.example.com", transport: method(:call), **options)
  end
end

def request(method = "GET", headers: {}, cookies: {}, host: "app.example.com", scheme: "https", path: "/")
  { method: method, scheme: scheme, host: host, path: path, headers: headers, cookies: cookies }
end

class SharedVectorsTest < Minitest::Test
  # The same tokens must get the same verdict in every server SDK (spec/server).
  def test_cookie_hash
    VECTORS["cookie_hash"].each { |value, expected| assert_equal expected, Murkio.fnv1a32(value) }
  end

  VECTORS["cases"].each do |tc|
    define_method("test_vector_#{tc['name'].tr(' ', '_')}") do
      client = FakeApi.new(jwks: VECTORS["jwks"], application: VECTORS["application_id"], issuer: VECTORS["issuer"]).client
      case tc["expect"]
      when "valid"
        session = client.verify(tc["token"])
        assert_equal tc["session"]["user_id"], session.user_id
        assert_equal tc["session"]["session_id"], session.session_id
        assert_equal tc["session"]["roles"], session.roles
      when "expired"
        error = assert_raises(Murkio::TokenError) { client.verify(tc["token"]) }
        assert_equal "expired", error.reason
      else
        error = assert_raises(Murkio::TokenError) { client.verify(tc["token"]) }
        assert_equal "invalid", error.reason
      end
    end
  end
end

class ClientTest < Minitest::Test
  def setup
    @api = FakeApi.new
    @client = @api.client
    @token = @api.token(roles: ["admin"])
    @hash = Murkio.fnv1a32(KEY)
    @page = { "Accept" => "text/html", "Sec-Fetch-Mode" => "navigate" }
  end

  def test_refuses_secret_keys
    assert_raises(ArgumentError) { Murkio::Client.new(publishable_key: "sk_secret") }
  end

  def test_bootstrap_and_jwks_are_fetched_once
    2.times { @client.verify(@api.token) }
    assert_raises(Murkio::TokenError) { @client.verify(@api.token(kid: "rotated")) }
    assert_equal ["GET /v1/client", "GET /jwks.json"], @api.calls
  end

  def test_bearer_token_and_api_keys
    result = @client.authenticate(**request(headers: { "Authorization" => "Bearer #{@token}" }))
    assert_equal "user-1", result.session.user_id
    assert result.session.role?(:admin)
    assert_equal "missing", @client.authenticate(**request(headers: { "authorization" => "Bearer #{KEY}" })).reason
  end

  def test_cookie_and_csrf
    cookies = { "__Host-murkio_session_#{@hash}" => @token, "__Host-murkio_uat_#{@hash}" => "1" }
    refute_nil @client.authenticate(**request(cookies: cookies)).session
    blocked = @client.authenticate(**request("POST", cookies: cookies, headers: { "Sec-Fetch-Site" => "cross-site" }))
    assert_equal "csrf", blocked.reason
    assert blocked.signed_in_hint
    refute_nil @client.authenticate(**request("POST", cookies: cookies, headers: { "Sec-Fetch-Site" => "same-origin" })).session
    refute_nil @client.authenticate(**request("POST", cookies: cookies, headers: { "Origin" => "https://app.example.com" })).session
    assert_equal "csrf", @client.authenticate(**request("POST", cookies: cookies, headers: { "Origin" => "https://evil.example" })).reason
  end

  def test_cookie_names
    plain = { "murkio_session_#{@hash}" => @token }
    assert_equal "missing", @client.authenticate(**request(cookies: plain)).reason
    refute_nil @client.authenticate(**request(cookies: plain, host: "localhost:3000", scheme: "http")).session
    secure = { "__Secure-murkio_session_#{@hash}" => @token }
    assert_equal "missing", @client.authenticate(**request(cookies: secure)).reason
    refute_nil @api.client(cookie_domain: ".example.com").authenticate(**request(cookies: secure)).session
  end

  def test_expired_and_invalid
    assert_equal "expired", @client.authenticate(**request(headers: { "Authorization" => "Bearer #{@api.token(exp: 1)}" })).reason
    assert_equal "invalid", @client.authenticate(**request(headers: { "Authorization" => "Bearer #{@api.token(aud: 'app-2')}" })).reason
  end

  def test_user_and_revocation_are_cached
    headers = { "Authorization" => "Bearer #{@token}" }
    result = nil
    2.times { result = @client.authenticate(**request(headers: headers), load_user: true, check_revocation: true) }
    assert_equal "ana@example.com", result.user.email
    assert_equal 1, @api.calls.count("POST /v1/me")
    assert_equal 1, @api.calls.count("POST /v1/sessions/verify")

    revoked = @api.token(jti: "revoked")
    @api.revoked[revoked] = true
    result = @client.authenticate(**request(headers: { "Authorization" => "Bearer #{revoked}" }), check_revocation: true)
    assert_nil result.session
    assert_equal "revoked", result.reason
  end

  def test_protect
    _, response = @client.protect(**request(path: "/api"), required: true)
    assert_equal 401, response.status
    _, response = @client.protect(**request(path: "/dashboard?tab=1", headers: @page), required: true, sign_in_url: "/login")
    assert_equal [302, "/login?redirect=%2Fdashboard%3Ftab%3D1"], [response.status, response.headers["location"]]
    headers = { "Authorization" => "Bearer #{@token}" }
    assert_equal 403, @client.protect(**request(headers: headers), roles: ["owner"])[1].status
    assert_nil @client.protect(**request(headers: headers), roles: [:admin])[1]
    result, response = @client.protect(**request)
    assert_nil response
    assert_nil result.session
  end

  def test_handshake
    hint = { "__Host-murkio_uat_#{@hash}" => "1" }
    _, response = @client.protect(**request(headers: @page, cookies: hint), required: true)
    nonce = response.headers["content-security-policy"][/'nonce-([^']+)'/, 1]
    assert_equal 200, response.status
    assert_includes response.body, %(nonce="#{nonce}")
    assert_includes response.body, %(data-murkio-key="#{KEY}")
    assert_includes response.headers["content-security-policy"], "connect-src https://api.example.com;"
    assert_includes response.headers["set-cookie"], "murkio_handshake=1"
    assert_includes response.headers["set-cookie"], "HttpOnly"
    assert_equal "no-store", response.headers["cache-control"]

    assert_equal 401, @client.protect(**request(headers: @page, cookies: hint.merge("murkio_handshake" => "1")), required: true)[1].status
    assert_equal 401, @client.protect(**request(headers: @page, cookies: hint), required: true, handshake: false)[1].status
  end

  def test_page_helpers
    head = @client.head(after_login: "/home")
    assert_includes head, %(integrity="#{Murkio::Cdn::INTEGRITY}")
    assert_includes head, %(crossorigin="anonymous")
    assert_includes head, %(data-murkio-after-login="/home")
    assert_equal "<murkio-identity-canvas></murkio-identity-canvas>", @client.canvas
    assert_equal %(<murkio-identity-canvas class="&quot; onload=&quot;x" light-dom></murkio-identity-canvas>), @client.canvas(class_name: %(" onload="x), light_dom: true)
    assert_equal %(<murkio-identity-email-input class="input" placeholder="you@example.com"></murkio-identity-email-input>),
                 @client.email_input(class_name: "input", placeholder: "you@example.com")
    assert_equal %(<murkio-identity-login-button class="btn" label="Entrar"></murkio-identity-login-button>), @client.login_button("Entrar", class_name: "btn")

    inline = @client.bootstrap_script
    refute_includes inline, "</script><b>"
    assert_includes inline, "data-generated-at="
    payload = inline[%r{>(.*)</script>\z}m, 1]
    refute_includes payload, "\u2028"
    assert_equal "</script><b>&\u2028", JSON.parse(payload)["canvas"]["document"]["note"]
    refute_includes @api.client(script_url: "https://static.example.com/murkio.js").head, "integrity"
  end
end

class RackTest < Minitest::Test
  def setup
    @api = FakeApi.new
    @app = ->(env) { [200, {}, ["hello #{Murkio::Rack.get(env).session&.user_id || 'guest'}"]] }
  end

  def env(path = "/", headers = {})
    base = { "REQUEST_METHOD" => "GET", "PATH_INFO" => path, "QUERY_STRING" => "", "rack.url_scheme" => "https", "HTTP_HOST" => "app.example.com" }
    headers.each { |name, value| base["HTTP_#{name.upcase.tr('-', '_')}"] = value }
    base
  end

  def test_middleware
    optional = Murkio::Rack.new(@app, client: @api.client)
    assert_equal ["hello guest"], optional.call(env)[2]

    protected_app = Murkio::Rack.new(@app, client: @api.client, required: true, sign_in_url: "/login")
    assert_equal 401, protected_app.call(env("/api"))[0]
    status, headers, = protected_app.call(env("/dashboard", "Accept" => "text/html"))
    assert_equal [302, "/login?redirect=%2Fdashboard"], [status, headers["location"]]
    assert_equal ["hello user-1"], protected_app.call(env("/api", "Authorization" => "Bearer #{@api.token}"))[2]

    cookie = "__Host-murkio_session_#{Murkio.fnv1a32(KEY)}=#{@api.token}; other=1"
    assert_equal ["hello user-1"], optional.call(env("/", "Cookie" => cookie))[2]
  end

  def test_parse_cookies
    assert_equal({ "a" => "1", "b" => "x y" }, Murkio::Rack.parse_cookies("a=1; b=x%20y; a=2; empty="))
  end
end
