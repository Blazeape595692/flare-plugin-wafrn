# Wafrn for Flare

A [Flare](https://github.com/flaresocialapp/Flare) plugin for [Wafrn](https://codeberg.org/wafrn/wafrn),
the Tumblr-inspired social network that federates with the fediverse and Bluesky.

## Features

| Feature | Notes |
| --- | --- |
| Sign in | In-browser OAuth. Flare never sees your password. Works with any Wafrn server. |
| Timelines | Dashboard (default), Local, Explore |
| Posts | Detail view, full thread, like/unlike, reblog/unreblog, link cards, hashtags |
| Profiles | Profile pages with Posts and Media tabs, follow/unfollow |
| Notifications | All / Mentions / Likes filters, unread badge. Covers likes, reblogs, follows, emoji reactions, quotes, asks and bites. |
| Compose | Text, images/video/audio with alt text, content warnings, visibility, replies |
| Server detection | Typing a Wafrn server address picks this plugin automatically |

The plugin uses Wafrn's Mastodon-compatible API (`/api/v1`). That API doesn't offer
search, deleting posts, bookmarks, block/mute, polls or follower lists yet, so those
features aren't shown.

## Sign in

1. In Flare, add an account and type your Wafrn server's full address, e.g.
   `app.wafrn.net`. Wafrn won't appear in the suggested server boxes, and partial text
   won't find it; Flare only lists built-in platforms there.
2. Choose **Continue with Wafrn**, sign in on the page that opens and approve Flare.

## Install

In Flare, open **Settings → Plugins → Add → Install from GitHub**, enter
`https://github.com/Blazeape595692/flare-plugin-wafrn`, review the permissions and confirm.
Flare checks this repository for new tagged versions.
