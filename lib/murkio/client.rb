# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "securerandom"
require "uri"

module Murkio
  DEFAULT_API_URL = "https://api.mukio.com"

  # The access token was refused. +reason+ is "invalid" or "expired".
  class TokenError < StandardError
    attr_reader :reason

    def initialize(message = "invalid token", reason: "invalid")
      super(message)
      @reason = reason
    end
  end

  # An error answer of the identity API.
  class ApiError < StandardError
    attr_reader :status, :code

    def initialize(status, code)
      super("murkio: api answered #{status} (#{code})")
      @status = status
      @code = code
    end
  end

  # A verified access token.
  Session = Struct.new(:user_id, :session_id, :application_id, :roles, :claims, :token, keyword_init: true) do
    def role?(*wanted)
      wanted.any? { |role| roles.include?(role.to_s) }
    end
  end

  # The profile of POST /v1/me.
  User = Struct.new(:id, :session_id, :email, :email_verified, :roles, :mfa_enabled, :created_at, keyword_init: true)

  # Who is behind a request. +session+ is nil when nobody is signed in;
  # +reason+ says why (missing, invalid, expired, revoked or csrf).
  AuthResult = Struct.new(:session, :user, :reason, :signed_in_hint, keyword_init: true)

  # An answer to send instead of running the route (401, 403, redirect or handshake).
  Response = Struct.new(:status, :headers, :body, keyword_init: true)

  # Verifies the sessions of one application. Create one per process and share it.
  #
  # The only setting is the publishable key (MURKIO_PUBLISHABLE_KEY): GET
  # /v1/client gives the application, the token issuer and the JWKS, and the
  # access tokens are verified locally (Ed25519, issuer, audience, expiry), so
  # a request costs no call to the API. The backend never signs anyone in: the
  # browser SDK does that, because the API rate-limits by the user's IP.
  class Client
    BOOTSTRAP_TTL = 60
    USER_TTL = 60
    REVOCATION_TTL = 30
    JWKS_RETRY = 60
    CACHE_LIMIT = 10_000
    SAFE_METHODS = %w[GET HEAD OPTIONS].freeze
    HANDSHAKE_GUARD = "murkio_handshake"
    # The DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw key follows.
    ED25519_SPKI_PREFIX = ["302a300506032b6570032100"].pack("H*").freeze

    attr_reader :publishable_key, :api_url, :key_hash

    def initialize(publishable_key: nil, api_url: nil, cookie_domain: nil, script_url: nil, integrity: nil, timeout: 10, transport: nil)
      key = publishable_key || ENV.fetch("MURKIO_PUBLISHABLE_KEY", "")
      unless key.start_with?("pk_")
        raise ArgumentError, "murkio: set publishable_key (or MURKIO_PUBLISHABLE_KEY) to the application's publishable key (pk_...)"
      end

      @publishable_key = key
      @api_url = (api_url || ENV["MURKIO_API_URL"] || DEFAULT_API_URL).sub(%r{/+\z}, "")
      @key_hash = Murkio.fnv1a32(key)
      @cookie_domain = cookie_domain
      @script_url = script_url || ENV["MURKIO_SCRIPT_URL"]
      @integrity = integrity || ENV["MURKIO_SCRIPT_INTEGRITY"]
      @transport = transport || method(:http_transport)
      @timeout = timeout
      @mutex = Mutex.new
      @bootstrap = nil
      @keys = {}
      @keys_at = nil
      @users = {}
      @actives = {}
    end

    # GET /v1/client: the application, its config and published canvas (cached a minute).
    def bootstrap
      @mutex.synchronize do
        return @bootstrap[1] if @bootstrap && monotonic - @bootstrap[0] < BOOTSTRAP_TTL
      end
      data = call("GET", "/v1/client")
      @mutex.synchronize { @bootstrap = [monotonic, data] }
      data
    end

    # Verifies an access token locally: an EdDSA signature by one of the
    # application's keys, the issuer, the audience (the application) and the
    # expiry. Raises TokenError (reason "expired" or "invalid").
    def verify(token)
      parts = token.to_s.split(".", -1)
      raise TokenError, "malformed token" unless parts.length == 3

      header = json_segment(parts[0])
      raise TokenError, "unsupported algorithm" unless header["alg"] == "EdDSA"

      application = bootstrap
      key = public_key(application, header["kid"].to_s)
      signature = decode_segment(parts[2])
      valid = begin
        signature.bytesize == 64 && key.verify(nil, signature, "#{parts[0]}.#{parts[1]}")
      rescue OpenSSL::PKey::PKeyError
        false
      end
      raise TokenError, "invalid signature" unless valid

      claims = json_segment(parts[1])
      expires = claims["exp"]
      unless claims["iss"] == application["issuer"] && claims["aud"] == application["application_id"] &&
             present?(claims["sub"]) && present?(claims["sid"]) && expires.is_a?(Numeric)
        raise TokenError, "invalid claims"
      end
      raise TokenError.new("expired token", reason: "expired") if Time.now.to_i >= expires

      Session.new(
        user_id: claims["sub"], session_id: claims["sid"], application_id: application["application_id"],
        roles: claims["roles"].is_a?(Array) ? claims["roles"].map(&:to_s) : [], claims: claims, token: token
      )
    end

    # The profile of the session's user (POST /v1/me), cached a minute per session.
    def user(session)
      cached(@users, session.session_id, USER_TTL) do
        data = call("POST", "/v1/me", { access_token: session.token })
        User.new(
          id: data["id"], session_id: data["session_id"], email: data["email"], email_verified: data["email_verified"] == true,
          roles: Array(data["roles"]).map(&:to_s), mfa_enabled: data["mfa_enabled"] == true, created_at: data["created_at"]
        )
      end
    end

    # False when the API says the session was revoked (logout, ban). Cached 30 s.
    def active?(session)
      cached(@actives, (session.claims["jti"] || session.token).to_s, REVOCATION_TTL) do
        call("POST", "/v1/sessions/verify", { access_token: session.token })["active"] == true
      end
    end

    # Finds and verifies the session of a request.
    #
    # The token comes from +Authorization: Bearer+ or from the session cookie
    # the browser SDK writes. The cookie goes with every request to the site,
    # including ones another site makes the browser send, so it only counts
    # for GET, HEAD and OPTIONS or for same-origin requests.
    #
    # +headers+ are looked up without case; +cookies+ is a name => value hash.
    def authenticate(method:, scheme:, host:, headers:, cookies:, load_user: false, check_revocation: false, **)
      headers = headers.to_h { |name, value| [name.to_s.downcase, value.to_s] }
      names = cookie_names(host)
      result = AuthResult.new(signed_in_hint: names.any? { |_, uat| cookies[uat] == "1" })

      token = nil
      authorization = headers["authorization"].to_s
      if authorization.start_with?("Bearer ")
        value = authorization[7..].strip
        token = value unless value.start_with?("pk_", "sk_")
      end
      unless token
        token = names.map { |name, _| cookies[name] }.find { |value| present?(value) }
        unless token
          result.reason = "missing"
          return result
        end
        unless SAFE_METHODS.include?(method.to_s.upcase) || same_origin?(headers, scheme, host)
          result.reason = "csrf"
          return result
        end
      end

      begin
        session = verify(token)
      rescue TokenError => e
        result.reason = e.reason
        return result
      end

      if check_revocation
        active = begin
          active?(session)
        rescue ApiError, SystemCallError, Timeout::Error, SocketError
          false
        end
        unless active
          result.reason = "revoked"
          return result
        end
      end
      if load_user
        result.user = begin
          user(session)
        rescue ApiError, SystemCallError, Timeout::Error, SocketError
          nil
        end
      end
      result.session = session
      result
    end

    # Authenticates a request and decides what to answer: the second item is a
    # Response to send instead of running the route (401, 403, a redirect to
    # +sign_in_url+ or the handshake page that refreshes an expired session
    # cookie), or nil to go on.
    def protect(method:, scheme:, host:, path:, headers:, cookies:, required: false, roles: nil, sign_in_url: nil,
                handshake: true, load_user: false, check_revocation: false)
      result = authenticate(method: method, scheme: scheme, host: host, headers: headers, cookies: cookies,
                            load_user: load_user, check_revocation: check_revocation)
      roles = Array(roles).map(&:to_s)
      if result.session
        return [result, json_response(403, "forbidden")] if roles.any? && !result.session.role?(*roles)

        return [result, nil]
      end

      lower = headers.to_h { |name, value| [name.to_s.downcase, value.to_s] }
      navigation = method.to_s.upcase == "GET" &&
                   (lower["sec-fetch-mode"] == "navigate" || lower["accept"].to_s.include?("text/html"))
      if handshake && navigation && result.signed_in_hint && %w[missing expired].include?(result.reason) &&
         !present?(cookies[HANDSHAKE_GUARD])
        return [result, handshake_response(scheme)]
      end

      return [result, nil] unless required || roles.any?

      if navigation && present?(sign_in_url)
        separator = sign_in_url.include?("?") ? "&" : "?"
        location = "#{sign_in_url}#{separator}redirect=#{URI.encode_www_form_component(path)}"
        return [result, Response.new(status: 302, headers: { "location" => location, "cache-control" => "no-store" }, body: "")]
      end
      [result, json_response(401, "unauthorized")]
    end

    # --- pages ---------------------------------------------------------------

    # The <script> that loads the browser SDK, pinned with its SRI hash. Put it in <head>.
    def head(after_login: nil, locale: nil, oauth_redirect_url: nil, nonce: nil)
      safe(script_tag(nonce: nonce, after_login: after_login, locale: locale, oauth_redirect_url: oauth_redirect_url))
    end

    # Inlines GET /v1/client so the browser draws the canvas without fetching
    # it. <, >, & and the U+2028/U+2029 separators become \u escapes, so the
    # JSON cannot end the <script> tag.
    def bootstrap_script
      json = JSON.generate(bootstrap).gsub(/[<>&  ]/) { |char| format("\\u%04x", char.ord) }
      stamp = (Time.now.to_f * 1000).to_i
      safe(%(<script type="application/json" id="murkio-bootstrap" data-generated-at="#{stamp}">#{json}</script>))
    end

    # <murkio-identity-canvas>: the login canvas designed in the dashboard.
    def canvas(screen: nil, class_name: nil, locale: nil, light_dom: false)
      safe("<murkio-identity-canvas#{attributes(screen: screen, class: class_name, locale: locale)}#{light_dom ? ' light-dom' : ''}></murkio-identity-canvas>")
    end

    def email_input(class_name: nil, placeholder: nil, label: nil, form: nil)
      field("murkio-identity-email-input", class: class_name, form: form, placeholder: placeholder, label: label)
    end

    def password_input(class_name: nil, placeholder: nil, label: nil, form: nil)
      field("murkio-identity-password-input", class: class_name, form: form, placeholder: placeholder, label: label)
    end

    def keep_logged(label, class_name: nil, form: nil)
      field("murkio-identity-keep-logged", class: class_name, form: form, label: label)
    end

    def login_button(label, class_name: nil, form: nil)
      field("murkio-identity-login-button", class: class_name, form: form, label: label)
    end

    def register_button(label, class_name: nil, form: nil)
      field("murkio-identity-register-button", class: class_name, form: form, label: label)
    end

    def error_message(class_name: nil, form: nil)
      field("murkio-identity-error", class: class_name, form: form)
    end

    private

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def present?(value)
      value.is_a?(String) && !value.empty?
    end

    def cached(store, key, ttl)
      @mutex.synchronize do
        hit = store[key]
        return hit[1] if hit && monotonic - hit[0] < ttl
      end
      value = yield
      @mutex.synchronize do
        store.clear if store.size >= CACHE_LIMIT
        store[key] = [monotonic, value]
      end
      value
    end

    def http_transport(method, url, headers, body)
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      request = Net::HTTP.const_get(method.capitalize).new(uri.request_uri, headers)
      request.body = body if body
      response = http.request(request)
      [response.code.to_i, response.body.to_s]
    end

    def call(method, path, body = nil)
      headers = { "Authorization" => "Bearer #{@publishable_key}", "Accept" => "application/json" }
      payload = nil
      if body
        headers["Content-Type"] = "application/json"
        payload = JSON.generate(body)
      end
      status, raw = @transport.call(method, @api_url + path, headers, payload)
      decoded = begin
        JSON.parse(raw.to_s)
      rescue JSON::ParserError
        {}
      end
      unless status.between?(200, 299) && decoded.is_a?(Hash) && decoded["data"].is_a?(Hash)
        code = decoded.is_a?(Hash) ? decoded.dig("details", 0, "code") : nil
        raise ApiError.new(status, (code || "http-#{status}").to_s)
      end
      decoded["data"]
    end

    # The signing key of +kid+. The JWKS is fetched again only for an unknown
    # kid (a key rotation), at most once a minute.
    def public_key(application, kid)
      @mutex.synchronize do
        return @keys[kid] if @keys.key?(kid)
        raise TokenError, "unknown key" if @keys_at && monotonic - @keys_at < JWKS_RETRY

        @keys_at = monotonic
      end

      url = URI.join("#{@api_url}/", application["jwks_url"].to_s).to_s
      status, raw = @transport.call("GET", url, { "Accept" => "application/json" }, nil)
      raise ApiError.new(status, "http-#{status}") unless status == 200

      keys = {}
      Array(JSON.parse(raw)["keys"]).each do |jwk|
        next unless jwk.is_a?(Hash) && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519"

        material = begin
          decode_segment(jwk["x"].to_s)
        rescue TokenError
          next
        end
        next unless material.bytesize == 32

        keys[jwk["kid"].to_s] = OpenSSL::PKey.read(ED25519_SPKI_PREFIX + material)
      end
      @mutex.synchronize { @keys = keys }
      keys.fetch(kid) { raise TokenError, "unknown key" }
    end

    def decode_segment(segment)
      raise TokenError, "malformed token" if segment.empty? || segment.match?(/[^A-Za-z0-9_-]/)

      (segment.tr("-_", "+/") + ("=" * ((4 - (segment.length % 4)) % 4))).unpack1("m0")
    rescue ArgumentError
      raise TokenError, "malformed token"
    end

    def json_segment(segment)
      value = JSON.parse(decode_segment(segment))
      raise TokenError, "malformed token" unless value.is_a?(Hash)

      value
    rescue JSON::ParserError, EncodingError
      raise TokenError, "malformed token"
    end

    def cookie_names(host)
      names = [["__Host-murkio_session_#{@key_hash}", "__Host-murkio_uat_#{@key_hash}"]]
      names << ["__Secure-murkio_session_#{@key_hash}", "__Secure-murkio_uat_#{@key_hash}"] if present?(@cookie_domain)
      hostname = host.to_s.sub(/:\d+\z/, "").delete("[]")
      names << ["murkio_session_#{@key_hash}", "murkio_uat_#{@key_hash}"] if %w[localhost 127.0.0.1 ::1].include?(hostname)
      names
    end

    def same_origin?(headers, scheme, host)
      site = headers["sec-fetch-site"]
      return site == "same-origin" if present?(site)

      present?(headers["origin"]) && headers["origin"] == "#{scheme}://#{host}"
    end

    def json_response(status, message)
      Response.new(status: status, headers: { "content-type" => "application/json", "cache-control" => "no-store" },
                   body: JSON.generate({ error: message }))
    end

    def handshake_response(scheme)
      nonce = SecureRandom.urlsafe_base64(16)
      script = URI.parse(@script_url || Cdn::URL)
      script_origin = script.host ? "#{script.scheme}://#{script.host}#{script.port == script.default_port ? '' : ":#{script.port}"}" : "https://cdn.jsdelivr.net"
      api = URI.parse(@api_url)
      api_origin = "#{api.scheme}://#{api.host}#{api.port == api.default_port ? '' : ":#{api.port}"}"
      page = <<~HTML.chomp
        <!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title>
        #{script_tag(nonce: nonce)}
        <script nonce="#{nonce}">(async function(){try{var m=window.Murkio&&window.Murkio.getMurkio();if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>
        </head><body></body></html>
      HTML
      Response.new(
        status: 200,
        headers: {
          "content-type" => "text/html; charset=utf-8",
          "cache-control" => "no-store",
          "content-security-policy" => "default-src 'none'; script-src 'nonce-#{nonce}' #{script_origin}; connect-src #{api_origin}; base-uri 'none'; frame-ancestors 'none'",
          "set-cookie" => "#{HANDSHAKE_GUARD}=1; Path=/; Max-Age=30; SameSite=Lax#{scheme == 'https' ? '; Secure' : ''}"
        },
        body: page
      )
    end

    def attributes(pairs)
      pairs.filter_map { |name, value| %( #{name}="#{escape(value.to_s)}") if present?(value.to_s) }.join
    end

    HTML_ESCAPES = { "&" => "&amp;", "<" => "&lt;", ">" => "&gt;", '"' => "&quot;", "'" => "&#39;" }.freeze

    def escape(value)
      value.gsub(/[&<>"']/, HTML_ESCAPES)
    end

    def script_tag(nonce: nil, after_login: nil, locale: nil, oauth_redirect_url: nil)
      integrity = @script_url ? @integrity : Cdn::INTEGRITY
      "<script#{attributes(
        "src" => @script_url || Cdn::URL, "integrity" => integrity, "crossorigin" => (present?(integrity) ? 'anonymous' : nil),
        "nonce" => nonce, "data-murkio-key" => @publishable_key, "data-murkio-api" => @api_url, "data-murkio-locale" => locale,
        "data-murkio-after-login" => after_login, "data-murkio-oauth-redirect" => oauth_redirect_url
      )}></script>"
    end

    def field(tag, pairs)
      safe("<#{tag}#{attributes(pairs)}></#{tag}>")
    end

    # Rails prints a String escaped unless it is html_safe. The helpers build
    # escaped markup, so they mark it safe when ActiveSupport is loaded.
    def safe(markup)
      markup.respond_to?(:html_safe) ? markup.html_safe : markup
    end
  end

  # The hash that names the cookies of a publishable key (same as @murkio/html).
  def self.fnv1a32(value)
    hash = 0x811c9dc5
    value.to_s.each_byte do |byte|
      hash ^= byte
      hash = (hash * 0x01000193) & 0xffffffff
    end
    format("%08x", hash)
  end
end
