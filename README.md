`tsid` is no longer maintained. Feel free to fork.

---

`tsid` is a [Caddy] plugin that allows access only to requests
coming from the [Tailscale] network and allows to identify users
behind these requests by setting some [Caddy] [placeholders]:

| Placeholder                  | Description |
|------------------------------|-------------|
| `{http.vars.tailscale.name}` | User name   |
| `{http.vars.tailscale.email}`| User email  |

## Usage

1. Build Caddy with this plugin by [xcaddy]:

        $ xcaddy build --with go.astrophena.name/tsid

2. Make sure that `tsid` is ordered first:

        {
          order tsid first
        }

3. Add the `tsid` directive to your Caddyfile and use the placeholders:

        tsid
        
        respond "Hello, {http.vars.tailscale.name}!"

## License

[MIT] © Ilya Mateyko

[Caddy]: https://caddyserver.com
[Tailscale]: https://tailscale.com
[placeholders]: https://caddyserver.com/docs/conventions#placeholders
[xcaddy]: https://github.com/caddyserver/xcaddy
[MIT]: LICENSE.md
