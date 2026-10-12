# Murkio identity for Ruby

Tells who is behind each request and writes the login components into the pages you
render. Rack middleware for Rails, Sinatra, Hanami or plain Rack. Ruby 3.1+, no
dependencies. The only setting is your publishable key.

```sh
gem install murkio
MURKIO_PUBLISHABLE_KEY=pk_...    # MURKIO_API_URL is optional
```

## Rails

```ruby
# config/initializers/murkio.rb
MURKIO = Murkio::Client.new
Rails.application.config.middleware.use Murkio::Rack, client: MURKIO   # env["murkio"] on every request

# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  helper_method :murkio_auth

  def murkio_auth = Murkio::Rack.get(request.env)

  def require_murkio!
    _, answer = MURKIO.protect(**Murkio::Rack.request(request.env), required: true, sign_in_url: "/login")
    return unless answer

    response.headers.merge!(answer.headers)
    render body: answer.body, status: answer.status
  end
end

# a protected controller
before_action :require_murkio!
```

```erb
<%# app/views/sessions/new.html.erb %>
<% content_for :head do %><%= MURKIO.head(after_login: "/dashboard") %><%= MURKIO.bootstrap_script %><% end %>
<%= MURKIO.canvas %>
```

## Sinatra / plain Rack

```ruby
murkio = Murkio::Client.new
use Murkio::Rack, client: murkio, required: true, sign_in_url: "/login", load_user: true

get "/dashboard" do
  "Hello #{Murkio::Rack.get(env).user.email}"
end
```

Options of the middleware and of `protect`: `required`, `roles`, `sign_in_url`,
`handshake`, `load_user`, `check_revocation`.

## Your own layout

```erb
<%= MURKIO.email_input(class_name: "input", placeholder: "you@example.com") %>
<%= MURKIO.password_input(class_name: "input") %>
<%= MURKIO.keep_logged("Keep me signed in") %>
<%= MURKIO.login_button("Sign in", class_name: "btn") %>
<%= MURKIO.register_button("Create account", class_name: "btn") %>
<%= MURKIO.error_message %>
```

The helpers return escaped markup, marked `html_safe` under Rails.

## How it works

The same contract as the other server SDKs (`libs/spec/server`): `GET /v1/client` gives
the application, issuer and JWKS; access tokens are verified locally (Ed25519 with
OpenSSL, `iss`, `aud`, `exp`); the token comes from `Authorization: Bearer` or the
`__Host-` session cookie of the browser SDK, which only counts for GET/HEAD/OPTIONS or
same-origin requests (CSRF). `load_user` reads `POST /v1/me` (cached a minute);
`check_revocation` asks the API whether the session was revoked (cached 30 s). A page
request with an expired cookie gets a short handshake page that refreshes it. The
backend never signs anyone in: the browser does.

## Developing

```sh
ruby -w -Ilib -Itest test/test_murkio.rb
```

The tests read the token vectors every Murkio server SDK shares. That copy (`spec/`) and
the checks in `infra/pipeline/` are kept in the Murkio identity service and synced from
there, so they are not edited here.

Every pull request runs the workflows in `.github/workflows`. The same checks, locally
(`bundle install` brings the tools):

| Workflow | What it runs |
| --- | --- |
| Build | `gem build murkio.gemspec --strict`, then requires the gem from what was packaged; on Ruby 3.1 and 4.0 |
| Format | `bundle exec rubocop --only Layout` |
| Lint | `bundle exec rubocop` |
| Tests | the suite, with warnings on, on Ruby 3.1 and 4.0 |
| Quality & Governance Checks | `for check in infra/pipeline/*.py; do python3 "$check"; done` |
| Security | `bundle exec bundle-audit check --update`, `gitleaks git .`, `zizmor --pedantic .` |
| CodeQL, Dependency Review | run by GitHub on the pull request |

Security reports: see [SECURITY.md](SECURITY.md).
