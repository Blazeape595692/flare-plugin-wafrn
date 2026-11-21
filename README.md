# Wafrn for Flare

A [Flare](https://github.com/flaresocialapp/Flare) plugin for [Wafrn](https://codeberg.org/wafrn/wafrn),
the Tumblr-inspired social network that federates with the fediverse and Bluesky.

## Features

| Feature | Notes |
| --- | --- |
| Sign in | Email and password (needed for emoji reactions), or in-browser authorization. Works with any Wafrn server. |
| Timelines | Following (default), Local, Wafrn & Friends. Following and Wafrn & Friends also come in "(no Bluesky)" versions you can add as tabs, which hide Bluesky (ATproto) posts and reposts, including Bluesky accounts bridged in through Bridgy Fed (`@bsky.brid.gy`). |
| Posts | Detail view, full thread, like/unlike, reblog/unreblog, delete your own posts (needs the email+password sign-in; Wafrn has no delete for browser sign-in), link cards, hashtags, custom emoji shown inline in posts and bios (Flare shows display names as plain text, so emoji there stay as `:name:`) |
| Quote posts | The quoted post is shown inside the quoting post, including in quote notifications |
| Emoji reactions | Reactions with counts and your server's custom emojis. Tap one to add or remove yours. Your profile (Me in the account menu) has an Emotes tab listing every emote on your server with its `:code:` to type in posts and replies; shown as a grid; tap one to see it large with its code underneath, then long-press the code to copy it. |
| Search | People (either sign-in) and posts by tag or text (needs the email+password sign-in) |
| Bookmarks | Your profile has a Bookmarks tab (between Media and Emotes) listing your Wafrn bookmarks; needs the email+password sign-in. Wafrn has no way for apps to list your likes. |
| Profiles | Profile pages with Posts and Media tabs, follow/unfollow |
| Notifications | All / Mentions / Likes filters, unread badge. Covers likes, reblogs, follows, emoji reactions, quotes, asks and bites. |
| Compose | Text, images/video/audio with alt text, content warnings, visibility, replies |
| Server detection | Typing a Wafrn server address picks this plugin automatically |

Not available yet, because Wafrn's API for apps doesn't offer them: search, deleting
posts, bookmarks, block/mute, polls and follower lists.

## Emoji reactions

Flare has no emoji picker for plugins, so:

- A post shows the reactions it already has. Tap one to add the same reaction; tap
  again to remove it.
- To react with any other emoji, **reply with only that emoji** (e.g. `🎉`) or only a
  custom emoji code (e.g. `:blobcat:`). That adds a reaction instead of posting a reply.
  Anything longer is a normal reply.
- Custom emojis from other servers are shown but can't be added from Flare, because
  Wafrn only accepts your own server's emojis there.
- Reactions need the **Sign in with email and password** option. With browser sign-in
  you see reactions but can't add any. Your password is only used to sign in and isn't
  stored.

## Sign in

1. In Flare, add an account and type your Wafrn server's full address, e.g.
   `app.wafrn.net`. Wafrn won't appear in the suggested server boxes, and partial text
   won't find it; Flare only lists built-in platforms there.
2. Choose **Sign in with email and password** (add your two-factor code if you use one),
   or **Continue with Wafrn** to sign in on the page that opens instead.

## Install

In Flare, open **Settings → Plugins → Add → Install from GitHub**, enter
`https://github.com/Blazeape595692/flare-plugin-wafrn`, review the permissions and confirm.
Flare checks this repository for new tagged versions.
