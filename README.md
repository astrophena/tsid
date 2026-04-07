`tsid` is a [Caddy] plugin that allows access only to requests coming from the
[Tailscale] network and allows to identify users behind these requests by
setting some [Caddy] [placeholders]:

| Placeholder                               | Description                                                |
| ----------------------------------------- | ---------------------------------------------------------- |
| `{http.vars.tailscale.id}`                | User's Tailscale ID                                        |
| `{http.vars.tailscale.name}`              | User's display name (e.g., "John Doe")                     |
| `{http.vars.tailscale.email}`             | User's login name or email address                         |
| `{http.vars.tailscale.profile_pic_url}`   | URL to the user's Tailscale profile picture                |
| `{http.vars.tailscale.node.id}`           | Tailscale ID of the connecting node                        |
| `{http.vars.tailscale.node.name}`         | Name of the connecting node                                |
| `{http.vars.tailscale.node.os}`           | Operating system of the node                               |
| `{http.vars.tailscale.node.os_version}`   | OS version of the node                                     |
| `{http.vars.tailscale.node.device_model}` | Device model of the node (usually set for mobile devices)  |
| `{http.vars.tailscale.node.machine}`      | Machine architecture of the node (e.g., `x86_64`, `arm64`) |

## Usage

1. Build Caddy with this plugin by [xcaddy]:

       $ xcaddy build --with go.astrophena.name/tsid

2. Add the `tsid` directive to your Caddyfile and use the placeholders:

       tsid

       respond "Hello, {http.vars.tailscale.name}!"

## License

[ISC] © Ilya Mateyko

[Caddy]: https://caddyserver.com
[Tailscale]: https://tailscale.com
[placeholders]: https://caddyserver.com/docs/conventions#placeholders
[xcaddy]: https://github.com/caddyserver/xcaddy
[ISC]: LICENSE.md
