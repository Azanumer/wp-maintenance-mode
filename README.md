# WP Maintenance Mode

A lightweight WordPress maintenance-mode plugin with proper SEO handling: visitors get a `503 Service Unavailable` page with a `Retry-After` header so search engines come back instead of de-indexing you.

## Features

- **503 + `Retry-After` header** — search-engine-friendly; never blocks `wp-login.php`, admin, AJAX, cron, or WP-CLI
- **Admin bypass cookie** — signed with the site's `AUTH_KEY`/`AUTH_SALT`, so enabling maintenance mode never locks *you* out; set automatically when you flip the switch, cleared when you turn it off
- **IP allow-list** — plain IPs or CIDR ranges (one per line), IPv4 + IPv6
- **Auto-off timer** — maintenance disables itself after N hours, so it can never be left on by accident
- **Custom title + message** — basic HTML allowed; clean dark holding page, `noindex, nofollow` meta tag
- **Admin preview** — `?wmm_preview=1` shows the page to admins while it's off
- **Uninstall-safe** — `uninstall.php` removes the settings option

## Install

1. Copy `wp-maintenance-mode.php` and `uninstall.php` into `wp-content/plugins/wp-maintenance-mode/`
2. Activate the plugin
3. Go to **Settings → Maintenance Mode**, customize, and check **Enable**

## Settings

| Setting | What it does |
|---|---|
| Enable | Puts the site into maintenance mode |
| Page title / Message | Text on the holding page (HTML allowed, sanitized) |
| Retry-After | Seconds sent in the `Retry-After` header (min 60) |
| Auto-disable after | Hours until maintenance turns itself off (empty = never) |
| Allowed IPs | Visitor IPs/CIDR ranges that skip maintenance mode |

## How the bypass works

On `template_redirect` the plugin checks, in order: WP-CLI → admin/AJAX/cron → login page → preview param → enabled flag → auto-off timer → bypass cookie → IP allow-list → **serve 503**.

The cookie value is `1|<timestamp>|<hmac-sha256 of "1" keyed by wp_salt('auth')>`, so it can't be forged by a visitor.

MIT licensed. Contributions welcome.
