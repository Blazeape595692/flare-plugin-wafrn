// Wafrn adapter for Flare Social Plugin API v1.
//
// Wafrn (https://codeberg.org/wafrn/wafrn) is a Tumblr-inspired fediverse/Bluesky
// server. This plugin talks to its Mastodon-compatible API (/api/v1, /oauth), which
// supports dynamic OAuth app registration, so signing in happens in the browser and
// Flare never sees the password.
//
// Not exposed because Wafrn's Mastodon API does not provide them yet: search,
// deleting posts, bookmarks, block/mute, polls, follower/following lists.

// Each request gets its own limit, shorter than Flare's 30 seconds for a whole call, so a
// slow server fails that request (a normal error) instead of the call (a plugin crash).
var REQUEST_TIMEOUT_MS = 12000;
var DETECTOR_REQUEST_TIMEOUT_MS = 8000;
var SIDE_REQUEST_TIMEOUT_MS = 5000; // extras (reactions, quotes, read markers) that may be skipped

var WAFRN_CAPABILITIES = {
  "flare.datasource.timeline/v1": ["page"],
  "flare.datasource.profile/v1": ["byId", "byHandle", "timeline"],
  "flare.datasource.post/v1": ["detail", "context", "mutate", "delete"],
  "flare.datasource.relation/v1": ["state", "mutate"],
  "flare.datasource.notification/v1": ["page", "badge"],
  "flare.datasource.compose/v1": ["publish"],
  "flare.datasource.search/v1": ["posts", "profiles", "discoverPosts", "discoverProfiles", "discoverHashtags"],
};

var OAUTH_SCOPES = "read write follow";
var OOB_REDIRECT = "urn:ietf:wg:oauth:2.0:oob";

// Emoji reactions use Wafrn's own API (/api/emojiReact, /api/v3/post), which needs
// the session token from an email+password sign-in. Flare has no emoji picker for
// plugins, so posts also show a few zero-count "quick" chips, and replying with only
// an emoji or :shortcode: reacts instead of posting a reply.
var QUICK_UNICODE = ["😂", "😮", "😢"];
var QUICK_CUSTOM_COUNT = 2;
var EMOJI_CACHE_MS = 10 * 60 * 1000;
var emojiCache = {}; // origin -> { at, list }; disposable runtime cache
var emojiTabCache = {}; // origin -> list shown in the Custom emotes tab, for its older pages

var NOTIFICATION_TYPES = {
  mention: ["mention"],
  like: ["favourite", "pleroma:emoji_reaction"],
};

defineFlareSocialPlugin(guardPlugin("the Wafrn server", withOpenLinks("Wafrn", {
  detector: {
    async detect(request, context) {
      var origin = requireOrigin(request.origin || context.origin);
      var instance;
      try {
        // Flare gives a detector 10 s in all and refuses requests allowed to run longer.
        instance = (await apiRequest(origin, "/api/v2/instance", { timeoutMillis: DETECTOR_REQUEST_TIMEOUT_MS })).data;
      } catch (_) {
        return { match: "none", canonicalOrigin: origin };
      }
      if (!isWafrn(instance)) return { match: "none", canonicalOrigin: origin };
      return {
        match: "exact",
        canonicalOrigin: origin,
        software: "Wafrn",
        instance: mapInstance(instance, origin),
      };
    },
  },

  login: {
    oauth: {
      async begin(request, context) {
        var origin = requireOrigin(request.origin || context.origin);
        var instance = (await apiRequest(origin, "/api/v2/instance")).data;
        if (!isWafrn(instance)) validationError("This server does not identify itself as Wafrn");
        lastLimitedRequest = 0;
        var redirectUri = requiredString(request.redirectUri, "OAuth redirect URI is missing");
        var app = (
          await apiRequest(origin, "/api/v1/apps", {
            method: "POST",
            body: {
              type: "form",
              values: {
                client_name: "Flare",
                redirect_uris: redirectUri,
                scopes: OAUTH_SCOPES,
                website: "https://github.com/flaresocialapp/Flare",
              },
            },
          })
        ).data;
        if (!app || !app.client_id || !app.client_secret) {
          invalidResponse("Wafrn did not return OAuth client credentials");
        }
        return {
          type: "externalBrowser",
          url: addQuery(origin + "/oauth/authorize", {
            client_id: String(app.client_id),
            redirect_uri: redirectUri,
            response_type: "code",
            scope: OAUTH_SCOPES,
            state: requiredString(request.state, "OAuth state is missing"),
          }),
          pendingPayload: {
            clientId: String(app.client_id),
            clientSecret: String(app.client_secret),
            composeConfig: composeConfig(instance),
          },
        };
      },

      async resume(request, context) {
        var origin = requireOrigin(request.origin || context.origin);
        var pending = request.pendingPayload || {};
        var callback = request.callbackParameters || {};
        if (callback.error) validationError("Wafrn denied the authorization request");
        var code = requiredString(callback.code, "OAuth callback code is missing");
        var token = (
          await apiRequest(origin, "/oauth/token", {
            method: "POST",
            body: {
              type: "form",
              values: {
                grant_type: "authorization_code",
                code: code,
                client_id: requiredString(pending.clientId, "OAuth client ID is missing"),
                client_secret: requiredString(pending.clientSecret, "OAuth client secret is missing"),
                redirect_uri: requiredString(request.redirectUri, "OAuth redirect URI is missing"),
              },
            },
          })
        ).data;
        if (!token || !token.access_token) invalidResponse("Wafrn did not return an access token");
        var accessToken = String(token.access_token);
        var account = (await apiRequest(origin, "/api/v1/accounts/verify_credentials", { token: accessToken })).data;
        var profile = mapProfile(account, origin);
        var value = {
          accountId: profile.key.id,
          origin: origin,
          credential: { accessToken: accessToken },
          profile: profile,
          capabilities: WAFRN_CAPABILITIES,
        };
        if (pending.composeConfig) value.composeConfig = pending.composeConfig;
        return { type: "success", value: value };
      },
    },

    // Email + password sign-in: keeps Wafrn's session token for reactions and
    // obtains a normal API token through the out-of-band OAuth flow.
    password: {
      async begin(request, context) {
        var origin = requireOrigin(request.origin || context.origin);
        var v = request.values || {};
        var email = requiredString(v.email, "Enter your Wafrn email").trim();
        var password = requiredString(v.password, "Enter your Wafrn password");
        var code = String(v.code || "").replace(/\s+/g, "");
        var instance = (await apiRequest(origin, "/api/v2/instance")).data;
        if (!isWafrn(instance)) validationError("This server does not identify itself as Wafrn");
        lastLimitedRequest = 0;

        var login = (await oncePerSecond(origin, "/api/login", {
          method: "POST",
          body: { type: "json", value: { email: email, password: password } },
        })).data || {};
        if (login.success !== true || !login.token) {
          validationError(typeof login.message === "string" && login.message ? login.message : "Wafrn rejected the email or password");
        }
        var jwt = String(login.token);
        if (login.mfaRequired) {
          if (!code) validationError("This account uses two-factor authentication; enter your current code");
          var mfa = (await oncePerSecond(origin, "/api/login/mfa", {
            method: "POST",
            token: jwt,
            body: { type: "json", value: { token: code } },
          })).data || {};
          if (mfa.success !== true || !mfa.token) validationError("Wafrn rejected the two-factor code");
          jwt = String(mfa.token);
        }

        var app = (await oncePerSecond(origin, "/api/v1/apps", {
          method: "POST",
          body: { type: "form", values: { client_name: "Flare", redirect_uris: OOB_REDIRECT, scopes: OAUTH_SCOPES, website: "https://github.com/flaresocialapp/Flare" } },
        })).data;
        if (!app || !app.client_id || !app.client_secret) invalidResponse("Wafrn did not return OAuth client credentials");
        var grant = (await apiRequest(origin, "/api/v1/oauth/authorize", {
          method: "POST",
          token: jwt,
          body: { type: "json", value: { client_id: String(app.client_id), redirect_uri: OOB_REDIRECT, scope: OAUTH_SCOPES } },
        })).data || {};
        if (grant.success !== true || !grant.code) invalidResponse("Wafrn did not authorize Flare");
        var token = (await apiRequest(origin, "/oauth/token", {
          method: "POST",
          body: { type: "form", values: {
            grant_type: "authorization_code", code: String(grant.code),
            client_id: String(app.client_id), client_secret: String(app.client_secret), redirect_uri: OOB_REDIRECT,
          } },
        })).data;
        if (!token || !token.access_token) invalidResponse("Wafrn did not return an access token");
        var accessToken = String(token.access_token);
        var account = (await apiRequest(origin, "/api/v1/accounts/verify_credentials", { token: accessToken })).data;
        var profile = mapProfile(account, origin);
        return {
          type: "success",
          value: {
            accountId: profile.key.id,
            origin: origin,
            credential: { accessToken: accessToken, jwt: jwt },
            profile: profile,
            capabilities: WAFRN_CAPABILITIES,
            composeConfig: composeConfig(instance),
          },
        };
      },
    },
  },

  capabilities: {
    timeline: {
      async page(request, context) {
        var id = request.timelineId;
        if (id === "home") return statusPage(context, "/api/v1/timelines/home", request.page, {});
        if (id === "local") return statusPage(context, "/api/v1/timelines/public", request.page, { local: "true" });
        if (id === "explore") return statusPage(context, "/api/v1/timelines/public", request.page, {});
        // The same feeds without Bluesky (ATproto) posts, reposts of them, or Bluesky reposters.
        if (id === "home-nobsky") return statusPage(context, "/api/v1/timelines/home", request.page, {}, notBluesky);
        if (id === "explore-nobsky") return statusPage(context, "/api/v1/timelines/public", request.page, {}, notBluesky);
        unsupportedError("Unknown Wafrn timeline");
      },
    },

    profile: {
      async byId(request, context) {
        var data = (await authed(context, "/api/v1/accounts/" + encodeURIComponent(request.key.id))).data;
        return mapProfile(data, context.origin);
      },
      async byHandle(request, context) {
        var host = originHost(context.origin);
        var handle = requiredString(request.handle, "Profile handle is missing").trim().replace(/^@/, "");
        var suffix = "@" + host;
        if (handle.toLowerCase().slice(-suffix.length) === suffix) handle = handle.slice(0, -suffix.length);
        var data = (await authed(context, addQuery("/api/v1/accounts/lookup", { acct: handle }))).data;
        return mapProfile(data, context.origin);
      },
      async timeline(request, context) {
        if (request.tabId === "bookmarks") {
          if (String(request.profile.id) === String(context.accountId)) return bookmarkPage(context, request.page);
          return { items: [], endReached: true };
        }
        if (request.tabId === "emotes") {
          // Flare shows profile tabs on every profile; the list belongs on your own.
          if (String(request.profile.id) === String(context.accountId)) return emojiPage(context, request.page);
          return { items: [], endReached: true };
        }
        var params = {};
        if (request.tabId === "media" || (request.parameters && request.parameters.onlyMedia === "true")) {
          params.only_media = "true";
        }
        return statusPage(
          context,
          "/api/v1/accounts/" + encodeURIComponent(request.profile.id) + "/statuses",
          request.page,
          params,
        );
      },
    },

    post: {
      async detail(request, context) {
        if (/^emoji:/.test(request.key.id)) return { post: await emojiDetail(context, request.key.id) };
        var status = (await authed(context, "/api/v1/statuses/" + encodeURIComponent(request.key.id))).data;
        var item = mapTimelineItem(status, context);
        await enrichItems([item], context);
        return item.presentation ? { post: item.post, presentation: item.presentation } : { post: item.post };
      },
      async context(request, context) {
        if (/^emoji:/.test(request.key.id)) return { items: [{ type: "post", post: await emojiDetail(context, request.key.id) }], endReached: true };
        var id = encodeURIComponent(request.key.id);
        var detail = (await authed(context, "/api/v1/statuses/" + id)).data;
        var thread = (await authed(context, "/api/v1/statuses/" + id + "/context")).data || {};
        var values = [];
        asArray(thread.ancestors).forEach(function (s) { values.push(s); });
        values.push(detail);
        asArray(thread.descendants).forEach(function (s) { values.push(s); });
        var items = values.filter(Boolean).slice(0, 200).map(function (s) { return mapTimelineItem(s, context); });
        await enrichItems(items, context);
        return { items: items, endReached: true };
      },
      async delete(request, context) {
        await deletePost(context, request.key.id);
        return { type: "deleted" };
      },
      async mutate(request, context) {
        if (request.action === "Delete") {
          await deletePost(context, request.key.id);
          return { type: "deleted" };
        }
        if (request.action === "React" || request.action === "Unreact") {
          var reaction = String((request.parameters && request.parameters.reaction) || "");
          await sendReaction(context, request.key.id, reaction, request.action === "Unreact");
          return { type: "updatedPost", post: await refreshedPost(context, request.key.id) };
        }
        var suffix = {
          Favourite: "favourite",
          Unfavourite: "unfavourite",
          Repost: "reblog",
          Unrepost: "unreblog",
        }[request.action];
        if (!suffix) unsupportedError("Wafrn does not support this action");
        var path = "/api/v1/statuses/" + encodeURIComponent(request.key.id);
        var response = await authed(context, path + "/" + suffix, { method: "POST" });
        var status = response.data;
        // Reblogging returns the new reblog wrapper, so reload the original post instead.
        if (!status || String(status.id) !== request.key.id || status.reblog) {
          status = (await authed(context, path)).data;
        }
        // An updated post replaces the cached one completely, so include its reactions.
        var updated = { type: "post", post: mapPost(status, context) };
        await enrichItems([updated], context);
        return { type: "updatedPost", post: updated.post };
      },
    },

    search: {
      async posts(request, context) {
        return searchPosts(context, request.query, request.page);
      },
      async profiles(request, context) {
        return searchProfiles(context, request.query, request.page);
      },
      async discoverPosts(request, context) {
        return statusPage(context, "/api/v1/timelines/public", request.page, {});
      },
      async discoverProfiles() {
        return { items: [], endReached: true }; // Wafrn has no "suggested people" list for apps
      },
      async discoverHashtags() {
        return { items: [], endReached: true };
      },
    },

    relation: {
      async state(request, context) {
        var data = (await authed(context, addQuery("/api/v1/accounts/relationships", { "id[]": request.key.id }))).data;
        var rel = asArray(data)[0];
        if (!rel) notFound("Relationship not found");
        return mapRelation(rel, request.key);
      },
      async mutate(request, context) {
        var verb = { Follow: "follow", Unfollow: "unfollow" }[request.action];
        if (!verb) unsupportedError("Wafrn does not support this relationship action");
        var rel = (await authed(context, "/api/v1/accounts/" + encodeURIComponent(request.key.id) + "/" + verb, {
          method: "POST",
        })).data;
        return { type: "updatedRelation", relation: mapRelation(rel, request.key) };
      },
    },

    notification: {
      async page(request, context) {
        var page = request.page;
        var query = { limit: String(clamp(page.limit, 1, 80)) };
        var types = NOTIFICATION_TYPES[request.filterId || "all"];
        if (types) query["types[]"] = types;
        if (page.direction !== "refresh" && page.cursor) query.max_id = page.cursor;
        var values = asArray((await authed(context, addQuery("/api/v1/notifications", query))).data);
        var items = [];
        var quoteItems = [];
        values.forEach(function (n) {
          var item = mapNotification(n, context);
          if (item) items.push(item);
          if (item && item.type === "post" && n.type === "wafrn:quote") quoteItems.push(item);
        });
        // Only quote notifications need the extra lookup (to show the quoted post).
        await enrichItems(quoteItems, context);
        // Wafrn's unread badge counts notifications newer than the "notifications" marker.
        // Flare has no "mark as read" hook, so opening the full list (newest page) marks it read.
        if (page.direction === "refresh" && (!request.filterId || request.filterId === "all") && values[0] && values[0].id != null) {
          await markNotificationsRead(context, String(values[0].id));
        }
        var last = values[values.length - 1];
        if (!last || last.id == null) return { items: items, endReached: true };
        return { items: items, olderCursor: String(last.id), endReached: false };
      },
      async badge(request, context) {
        var data = (await authed(context, "/api/v1/notifications/unread_count")).data;
        return { value: Math.max(0, Math.floor(Number((data && data.count) || 0)) || 0) };
      },
    },

    compose: {
      async publish(request, context) {
        // Replying with only one emoji or :shortcode: reacts instead (Flare has no emoji picker).
        var reactWith = request.replyTo && !(request.assets || []).length && !request.spoilerText
          ? await reactionFromText(context, request.text) : null;
        if (reactWith) {
          await sendReaction(context, request.replyTo.id, reactWith, false);
          return { post: await refreshedPost(context, request.replyTo.id) };
        }
        var mediaIds = [];
        var assets = request.assets || [];
        for (var i = 0; i < assets.length; i++) {
          var asset = assets[i];
          var parts = [{
            type: "asset",
            name: "file",
            handle: asset.handle,
            fileName: asset.fileName || "upload",
            contentType: asset.mimeType || "application/octet-stream",
          }];
          if (asset.description) parts.push({ type: "text", name: "description", value: asset.description });
          var uploaded = (await authed(context, "/api/v2/media", {
            method: "POST",
            timeoutMillis: 120000,
            body: { type: "multipart", parts: parts },
          })).data;
          if (!uploaded || uploaded.id == null) invalidResponse("Wafrn did not return a media ID");
          mediaIds.push(String(uploaded.id));
        }
        if (!String(request.text || "").trim() && mediaIds.length === 0) {
          validationError("Write something or attach media");
        }
        var payload = {
          status: request.text || "",
          media_ids: mediaIds,
          visibility: toWafrnVisibility(request.visibility),
          spoiler_text: request.spoilerText || "",
        };
        if (request.replyTo) payload.in_reply_to_id = request.replyTo.id;
        if (request.languages && request.languages[0]) payload.language = request.languages[0];
        var response = await authed(context, "/api/v1/statuses", {
          method: "POST",
          timeoutMillis: 120000,
          body: { type: "json", value: payload },
        });
        if (response.status === 202 || !response.data) {
          // Wafrn queued the post instead of publishing it immediately.
          validationError("Wafrn queued the post; it will appear once published");
        }
        var created = { type: "post", post: mapPost(response.data, context) };
        await enrichItems([created], context);
        return { post: created.post };
      },
    },
  },
}, wafrnPageUrl)));

// Flare treats any error that isn't made with flare.error() as a plugin crash, and pauses
// the plugin after three in a minute. Every entry point therefore turns a stray error
// (a failed request, unexpected data) into an ordinary error Flare shows as a message.
function guardPlugin(name, definition) {
  function wrap(value) {
    if (typeof value === "function") {
      return async function () {
        try {
          return safeRichText(await value.apply(this, arguments));
        } catch (error) {
          if (error && error.__flarePluginErrorV1 !== undefined) throw error;
          var network = !!(error && typeof error.code === "string" && /^host\./.test(error.code));
          throw flare.error({
            code: network ? "Network" : "InvalidResponse",
            message: { value: network ? "Could not reach " + name : name + " sent something this plugin couldn't read" },
          });
        }
      };
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      var out = {};
      Object.keys(value).forEach(function (key) { out[key] = wrap(value[key]); });
      return out;
    }
    return value;
  }
  return wrap(definition);
}

// Flare rejects a whole result if any link or image in rich text isn't plain HTTPS
// (tumblr posts and bios often link to http:// sites or mailto: addresses). Before
// returning, upgrade http:// links to https://, and drop any link target or image
// Flare would still refuse, keeping the link's text.
function safeRichText(value) {
  if (Array.isArray(value)) return value.map(safeRichText);
  if (!value || typeof value !== "object") return value;
  var out = {};
  Object.keys(value).forEach(function (key) { out[key] = safeRichText(value[key]); });
  if (out.format === "html" && typeof out.value === "string") out.value = safeHtmlUrls(out.value);
  return out;
}

var RICH_URL_ATTR = { a: "href", img: "src", emoji: "target" };

function safeHtmlUrls(html) {
  return html.replace(/<(a|img|emoji)\b([^>]*)>/gi, function (tag, name, attrs) {
    var attrName = RICH_URL_ATTR[name.toLowerCase()];
    var re = new RegExp("(\\s" + attrName + "\\s*=\\s*)(\"[^\"]*\"|'[^']*'|[^\\s\"'>]+)", "i");
    var m = re.exec(attrs);
    if (!m) return tag;
    var raw = m[2].replace(/^["']|["']$/g, "");
    var url = safeRichUrl(raw);
    if (url) return "<" + name + attrs.slice(0, m.index) + m[1] + '"' + url.replace(/"/g, "&quot;") + '"' + attrs.slice(m.index + m[0].length) + ">";
    if (name.toLowerCase() === "img") return "";
    return "<" + name + attrs.slice(0, m.index) + attrs.slice(m.index + m[0].length) + ">";
  });
}

function safeRichUrl(raw) {
  var url = String(raw)
    .replace(/&amp;/gi, "&").replace(/&#0*58;|&#x0*3a;|&colon;/gi, ":").replace(/&#0*47;|&#x0*2f;|&sol;/gi, "/")
    .trim();
  if (/^http:\/\//i.test(url)) url = "https://" + url.slice(7);
  var m = /^https:\/\/([^\/?#\s]+)([\/?#][^\s"<>]*)?$/i.exec(url);
  if (!m || url.length > 8000) return null;
  if (!/^[A-Za-z0-9.-]+(?::\d{1,5})?$/.test(m[1]) || !/[A-Za-z0-9]/.test(m[1])) return null;
  return url.replace(/&/g, "&amp;");
}

async function markNotificationsRead(context, newestId) {
  try {
    var current = (await authed(context, addQuery("/api/v1/markers", { "timeline[]": "notifications" }), { timeoutMillis: SIDE_REQUEST_TIMEOUT_MS })).data;
    var last = current && current.notifications && current.notifications.last_read_id;
    if (last != null && Number(last) >= Number(newestId)) return; // never move the marker back
    await authed(context, "/api/v1/markers", {
      method: "POST",
      body: { type: "json", value: { notifications: { last_read_id: newestId } } },
      timeoutMillis: SIDE_REQUEST_TIMEOUT_MS,
    });
  } catch (_) {
    // A failed marker update only leaves the badge as it was; still show the list.
  }
}

// ------------------------------------------------------------------ paging

async function statusPage(context, path, page, params, keep) {
  var limit = clamp(page.limit, 1, 40);
  var cursor = page.direction !== "refresh" && page.cursor ? page.cursor : null;
  var kept = [];
  var last = null;
  // With a filter, a page can come back empty; fetch a few more pages before giving up.
  for (var round = 0; round < (keep ? 4 : 1); round++) {
    var query = Object.assign({}, params, { limit: String(limit) });
    if (cursor) query.max_id = cursor;
    var values = asArray((await authed(context, addQuery(path, query))).data).filter(Boolean);
    kept = kept.concat(keep ? values.filter(keep) : values);
    last = values[values.length - 1];
    // Wafrn's Link header may report http:// behind proxies, so page by the last ID.
    if (!last || last.id == null) { last = null; break; }
    cursor = String(last.id);
    if (kept.length >= Math.min(limit, 10)) break;
  }
  var items = kept.map(function (s) { return mapTimelineItem(s, context); });
  await enrichItems(items, context);
  if (!last) return { items: items, endReached: true };
  return { items: items, olderCursor: cursor, endReached: false };
}

function notBluesky(status) {
  return !isBlueskyAccount(status.account) && !isBlueskyStatus(status) &&
    !(status.reblog && (isBlueskyAccount(status.reblog.account) || isBlueskyStatus(status.reblog)));
}

// Bluesky content arrives two ways: Wafrn's own Bluesky link, and Bridgy Fed, which
// copies Bluesky accounts into the fediverse as handle@bsky.brid.gy.
var BLUESKY_URL = /^(at:\/\/|https:\/\/(bsky\.app|bsky\.brid\.gy)\/)/i;

function isBlueskyStatus(status) {
  return !!status && (BLUESKY_URL.test(String(status.uri || "")) || BLUESKY_URL.test(String(status.url || "")));
}

// Wafrn stores Bluesky users by their bare handle (alice.bsky.social), fediverse users as
// user@server, and local usernames can't contain dots.
function isBlueskyAccount(account) {
  if (!account) return false;
  var acct = String(account.acct || account.username || "").replace(/^@/, "").toLowerCase();
  if (acct && acct.indexOf("@") < 0 && acct.indexOf(".") >= 0) return true;
  if (/@bsky\.brid\.gy$/.test(acct)) return true;
  return BLUESKY_URL.test(String(account.url || ""));
}

// ------------------------------------------------- reactions and quotes
//
// Wafrn's Mastodon-style API has no reactions or quotes, so each shown post is
// looked up once in Wafrn's own API (/api/v3/post/:uuid), in parallel. A failed
// lookup only leaves that post without reactions/quotes.

async function enrichItems(items, context) {
  var targets = [];
  items.forEach(function (item) {
    if (!item || item.type !== "post") return;
    var post = item.presentation && item.presentation.repost ? item.presentation.repost : item.post;
    var uuid = decodeId(post.key.id);
    if (uuid) targets.push({ item: item, post: post, uuid: uuid });
  });
  if (!targets.length) return;
  var cred = (await flare.credential.read()) || {};
  var jwt = typeof cred.jwt === "string" && cred.jwt ? cred.jwt : null;
  if (!jwt) {
    // Without the email+password session Wafrn can't delete posts, so don't offer it.
    targets.forEach(function (t) {
      if (t.post.actions) t.post.actions = t.post.actions.filter(function (a) { return a.action !== "Delete"; });
    });
  }
  var me = decodeId(String(context.accountId || ""));
  // Fetch the emoji list and every post at once, each with a short limit, so a slow
  // server only drops the extras instead of the whole timeline.
  var emojis = jwt ? customEmojis(context) : Promise.resolve([]);
  var side = { timeoutMillis: SIDE_REQUEST_TIMEOUT_MS };
  if (jwt) side.token = jwt;
  var lookups = {};
  targets.forEach(function (t) {
    if (!lookups[t.uuid]) {
      lookups[t.uuid] = apiRequest(context.origin, "/api/v3/post/" + t.uuid, side)
        .then(function (r) { return r.data; }, function () { return null; });
    }
  });
  var emojiList = await emojis;
  var quick = jwt ? quickChips(context, emojiList) : [];
  // Wafrn can only react with this server's own custom emojis (looked up by :name:).
  var local = {};
  emojiList.forEach(function (e) { local[":" + e.shortcode + ":"] = true; });
  await Promise.all(targets.map(async function (t) {
    var data = await lookups[t.uuid];
    if (!data || typeof data !== "object") return;
    var inline = postEmojiMap(data, t.uuid, context.origin);
    if (Object.keys(inline).length) {
      t.post.content = { format: "html", value: emojify(t.post.content.value, inline) };
    }
    var reactions = buildReactions(data, t.uuid, me, !!jwt, quick, context.origin, local);
    if (reactions.length) t.post.emojiReactions = reactions;
    var quotes = quotedPosts(data, t.uuid, context);
    if (quotes.length) {
      t.item.presentation = t.item.presentation || {};
      t.item.presentation.quotes = quotes;
    }
  }));
}

function buildReactions(data, uuid, me, canReact, quick, origin, local) {
  var relations = data.emojiRelations || {};
  var emojis = {};
  asArray(relations.emojis).forEach(function (e) { if (e && e.id) emojis[e.id] = e; });
  var rows = asArray(relations.postEmojiReactions).filter(function (r) { return r && r.postId === uuid; });
  var counts = asArray(data.emojiReactionCounts).filter(function (c) { return c && c.postId === uuid && c.content; });
  if (!counts.length) {
    // Older servers send every reaction instead of per-emoji counts.
    var tally = {};
    rows.forEach(function (r) { tally[r.content] = (tally[r.content] || 0) + 1; });
    counts = Object.keys(tally).map(function (k) { return { content: k, count: tally[k] }; });
  }
  var out = [];
  var seen = {};
  counts.sort(function (a, b) { return Number(b.count) - Number(a.count); }).forEach(function (c) {
    var name = String(c.content);
    if (seen[name] || name.length > 512) return;
    var row = rows.filter(function (r) { return r.content === name; })[0];
    var custom = /^:[^:\s]+:$/.test(name);
    var mine = !!me && rows.some(function (r) { return r.content === name && r.userId === me; });
    // Other servers' emojis can be shown but not added (removing your own still works).
    var chip = { name: name, count: count(c.count), isUnicode: !custom, me: mine,
      enabled: canReact && (!custom || !!(local && local[name]) || mine) };
    if (custom) {
      var emoji = row && emojis[row.emojiId];
      var url = emoji && emoji.uuid ? emojiImageUrl(origin, emoji.uuid) : emoji && safeHttpsUrl(emoji.url, null);
      if (!url) return; // Flare needs an image for custom emoji
      chip.url = url;
    }
    seen[name] = true;
    out.push(chip);
  });
  quick.forEach(function (q) {
    if (!seen[q.name] && out.length < 100) {
      seen[q.name] = true;
      out.push(Object.assign({ count: 0, me: false, enabled: true }, q));
    }
  });
  return out.slice(0, 100);
}

function quotedPosts(data, uuid, context) {
  var byId = {};
  asArray(data.quotedPosts).forEach(function (p) { if (p && p.id) byId[p.id] = p; });
  var out = [];
  asArray(data.quotes).forEach(function (q) {
    var quoted = q && q.quoterPostId === uuid ? byId[q.quotedPostId] : null;
    if (quoted && out.length < 100) {
      var mapped = mapNativePost(quoted, data, context);
      if (mapped) out.push(mapped);
    }
  });
  return out;
}

/** Maps a post from Wafrn's own API to PostV1, keyed like the Mastodon API so it opens normally. */
function mapNativePost(p, data, context) {
  var origin = context.origin;
  var key = encodeId(String(p.id), p.createdAt);
  if (!key) return null;
  var post = {
    key: { id: key, host: originHost(origin) },
    createdAt: isoDate(p.createdAt),
    content: { format: "html", value: emojify(nativeAskHtml(p, data) + String(p.content || ""), postEmojiMap(data, p.id, origin)) },
    media: asArray(data.medias).filter(function (m) { return m && m.postId === p.id; }).map(function (m) {
      var type = String(m.mediaType || "");
      var kind = type.indexOf("video/") === 0 ? "video" : type.indexOf("audio/") === 0 ? "audio" : type === "image/gif" ? "gif" : type.indexOf("image/") === 0 || !type ? "image" : null;
      if (!kind || !m.id) return null;
      var media = { id: String(m.id), type: kind, url: requireOrigin(origin) + "/api/v2/cache/media/" + encodeURIComponent(m.id) };
      if (m.description) media.description = String(m.description);
      if (positive(m.width)) media.width = Math.round(m.width);
      if (positive(m.height)) media.height = Math.round(m.height);
      return media;
    }).filter(Boolean).slice(0, 100),
    url: requireOrigin(origin) + "/fediverse/post/" + encodeURIComponent(p.id),
  };
  var user = asArray(data.users).filter(function (u) { return u && u.id === p.userId; })[0];
  if (user && user.url) post.author = mapNativeUser(user, origin);
  if (p.content_warning) {
    post.spoilerText = String(p.content_warning);
    post.sensitive = true;
  }
  return post;
}

function mapNativeUser(u, origin) {
  var host = originHost(origin);
  var url = String(u.url);
  var remote = url.charAt(0) === "@";
  var acct = remote ? url.slice(1) : url;
  var profile = {
    // Wafrn's Mastodon API also accepts raw user IDs, so the profile still opens.
    key: { id: String(u.id), host: host },
    handle: "@" + (acct.indexOf("@") >= 0 ? acct : acct + "@" + host),
    displayName: String(u.name || acct),
    avatarUrl: requireOrigin(origin) + "/api/v2/cache/avatar/" + encodeURIComponent(u.id),
    bot: u.isBot === true,
  };
  var link = safeHttpsUrl(u.remoteId, null);
  if (link) profile.url = link;
  return profile;
}

// ------------------------------------------------------------ custom emoji
//
// Posts carry custom emoji as :shortcode: text. Flare draws <emoji target="url"> inline,
// so each known shortcode outside tags and links becomes one.

function mastodonEmojis(list, origin) {
  var map = {};
  asArray(list).forEach(function (e) {
    if (!e || !e.shortcode) return;
    var url = safeHttpsUrl(e.static_url || e.url, origin);
    if (url) map[":" + String(e.shortcode).replace(/^:|:$/g, "") + ":"] = url;
  });
  return map;
}

/** Emojis Wafrn's own API lists for one post (postEmojiRelation), by :name:. */
function postEmojiMap(data, postId, origin) {
  var relations = (data && data.emojiRelations) || {};
  var byId = {};
  asArray(relations.emojis).forEach(function (e) { if (e && e.id) byId[e.id] = e; });
  var map = {};
  asArray(relations.postEmojiRelation).forEach(function (r) {
    var e = r && r.postId === postId ? byId[r.emojiId] : null;
    if (!e || !e.name) return;
    var url = e.uuid ? emojiImageUrl(origin, e.uuid) : safeHttpsUrl(e.url, origin);
    if (url) map[":" + String(e.name).replace(/^:|:$/g, "") + ":"] = url;
  });
  return map;
}

function emojify(html, map) {
  if (!html || !map || !Object.keys(map).length || html.indexOf(":") < 0) return html;
  var depth = 0; // inside <a>, <code> or <pre>: leave text alone
  return html.split(/(<[^>]*>)/).map(function (part) {
    if (part.charAt(0) === "<") {
      var m = part.match(/^<(\/?)(a|code|pre)\b/i);
      if (m) depth = Math.max(0, depth + (m[1] ? -1 : 1));
      return part;
    }
    if (depth) return part;
    return part.replace(/:[A-Za-z0-9_+-]+:/g, function (code) {
      var url = map[code];
      return url ? '<emoji target="' + esc(url) + '" alt="' + esc(code) + '"></emoji>' : code;
    });
  }).join("");
}

function emojiImageUrl(origin, uuid) {
  return requireOrigin(origin) + "/api/v2/cache/emoji/" + encodeURIComponent(uuid) + "?format=webp&size=small";
}

// The Emotes profile tab (on your own profile): every custom emoji on this server with its :code:, so it can
// be looked up and typed into a post or reply. Rows open the emoji image when tapped.
async function emojiList(context, fresh) {
  if (fresh || !emojiTabCache[context.origin]) {
    emojiTabCache[context.origin] = asArray((await apiRequest(context.origin, "/api/v1/custom_emojis", {})).data)
      .filter(function (e) { return e && e.shortcode && safeHttpsUrl(e.url, context.origin); });
  }
  return emojiTabCache[context.origin];
}

// The Emotes tab is a grid. Tapping a tile opens Flare's viewer, which shows the emote
// large with this text under it, where the code can be long-pressed and copied.
function emojiPost(e, context, detail) {
  var code = ":" + String(e.shortcode) + ":";
  var url = safeHttpsUrl(e.url, context.origin);
  var img = safeHttpsUrl(e.static_url, context.origin) || url;
  var html = '<p><emoji target="' + esc(img) + '" alt="' + esc(code) + '"></emoji> ' + esc(code) + "</p>";
  if (detail) html = "<p>" + esc(code) + "</p><p><small>Long-press the code to select and copy it.</small></p>";
  if (e.category) html += "<p><small>" + esc(String(e.category)) + "</small></p>";
  var post = {
    key: { id: "emoji:" + String(e.shortcode), host: originHost(context.origin) },
    createdAt: new Date(0).toISOString(),
    content: { format: "html", value: html },
  };
  if (detail) post.media = [{ id: "emoji:" + String(e.shortcode), type: /\.gif(\?|$)/i.test(url) ? "gif" : "image", url: url, description: code }];
  return post;
}

async function emojiDetail(context, id) {
  var name = String(id).slice("emoji:".length);
  var find = function (list) { return list.filter(function (e) { return String(e.shortcode) === name; })[0]; };
  var e = find(await emojiList(context, false)) || find(await emojiList(context, true));
  if (!e) notFound("That emote is no longer on this server");
  return emojiPost(e, context, true);
}

async function emojiPage(context, page) {
  var list = await emojiList(context, page.direction === "refresh");
  list = list.slice().sort(function (a, b) {
    var ca = String(a.category || ""), cb = String(b.category || "");
    if (ca !== cb) return ca < cb ? -1 : 1;
    return String(a.shortcode).toLowerCase() < String(b.shortcode).toLowerCase() ? -1 : 1;
  });
  var start = page.direction !== "refresh" && /^\d+$/.test(String(page.cursor || "")) ? Number(page.cursor) : 0;
  var size = clamp(page.limit, 1, 40);
  var items = list.slice(start, start + size).map(function (e) { return { type: "post", post: emojiPost(e, context, true) }; });
  var next = start + size;
  return next < list.length ? { items: items, olderCursor: String(next), endReached: false } : { items: items, endReached: true };
}

async function customEmojis(context) {
  var cached = emojiCache[context.origin];
  if (cached && Date.now() - cached.at < EMOJI_CACHE_MS) return cached.list;
  var list = [];
  try {
    list = asArray((await apiRequest(context.origin, "/api/v1/custom_emojis", { timeoutMillis: SIDE_REQUEST_TIMEOUT_MS })).data)
      .filter(function (e) { return e && e.shortcode && safeHttpsUrl(e.url, context.origin); });
  } catch (_) {
    list = cached ? cached.list : [];
  }
  emojiCache[context.origin] = { at: Date.now(), list: list };
  return list;
}

function quickChips(context, emojiList) {
  var chips = QUICK_UNICODE.map(function (e) { return { name: e, isUnicode: true }; });
  emojiList.slice(0, QUICK_CUSTOM_COUNT).forEach(function (e) {
    chips.push({ name: ":" + e.shortcode + ":", isUnicode: false, url: safeHttpsUrl(e.url, context.origin) });
  });
  return chips;
}

// Deletes one of your posts through Wafrn's own API.
async function deletePost(context, postKey) {
  var status = (await authed(context, "/api/v1/statuses/" + encodeURIComponent(postKey))).data;
  if (!isOwnPost(status, context)) validationError("You can only delete your own posts");
  var cred = (await flare.credential.read()) || {};
  // Wafrn's Mastodon-style API has no delete; only its own API (which needs the
  // email+password sign-in's session) can delete posts.
  if (!cred.jwt) unsupportedError("Deleting posts needs the \"Sign in with email and password\" option; add the account again that way");
  var uuid = decodeId(postKey);
  if (!uuid) notFound("Unknown Wafrn post");
  var result = (await apiRequest(context.origin, addQuery("/api/deletePost", { id: uuid }), {
    method: "DELETE",
    token: String(cred.jwt),
  })).data || {};
  if (result.success !== true) fail("Remote", remoteMessage(result, "Wafrn couldn't delete this post"));
}

// The Bookmarks tab on your own profile. Only Wafrn's own API lists bookmarks (dashboard
// level 50, newest post first, paged by the last post's time), and it needs the
// email+password sign-in's session.
async function bookmarkPage(context, page) {
  var cred = (await flare.credential.read()) || {};
  if (!cred.jwt) unsupportedError("Bookmarks need the \"Sign in with email and password\" option; add the account again that way");
  var query = { level: "50" };
  var cursor = page.direction !== "refresh" && /^\d{1,15}$/.test(String(page.cursor || "")) ? String(page.cursor) : null;
  if (cursor) query.startScroll = cursor; else query.page = "-1";
  var data = (await apiRequest(context.origin, addQuery("/api/v2/dashboard", query), { token: String(cred.jwt) })).data || {};
  var posts = asArray(data.posts).filter(function (p) { return p && p.id; });
  var items = nativePostItems(posts, data, context);
  var last = posts[posts.length - 1];
  var lastTime = last ? Date.parse(last.createdAt) : NaN;
  if (!posts.length || !Number.isFinite(lastTime)) return { items: items, endReached: true };
  return { items: items, olderCursor: String(lastTime), endReached: false };
}

/** Posts from Wafrn's own API as timeline items; a reblog with no text shows what it reblogged. */
function nativePostItems(posts, data, context) {
  var items = [];
  posts.forEach(function (p) {
    var shown = p;
    if (!String(p.content || "").trim() && p.parentId) {
      shown = asArray(p.ancestors).filter(function (a) { return a && a.id === p.parentId; })[0] ||
        asArray(data.posts).filter(function (a) { return a && a.id === p.parentId; })[0] || p;
    }
    var mapped = mapNativePost(shown, data, context);
    if (mapped && items.length < 200) items.push({ type: "post", post: mapped });
  });
  return items;
}

// Search. People come from the Mastodon-style API (works with either sign-in). Posts
// only from Wafrn's own search (tags first, then text), which needs the email+password
// sign-in's session.
async function searchPosts(context, query, page) {
  var term = String(query || "").trim().replace(/^#/, "");
  if (!term) return { items: [], endReached: true };
  var cred = (await flare.credential.read()) || {};
  if (!cred.jwt) unsupportedError("Searching posts needs the \"Sign in with email and password\" option; add the account again that way. Searching people works either way.");
  var n = page.direction !== "refresh" && /^\d{1,4}$/.test(String(page.cursor || "")) ? Number(page.cursor) : 0;
  var data = (await apiRequest(context.origin, addQuery("/api/v2/search", { term: term, page: String(n) }), { token: String(cred.jwt) })).data || {};
  var found = data.posts || {};
  var posts = asArray(found.posts).filter(function (p) { return p && p.id; });
  var items = nativePostItems(posts, found, context);
  return posts.length ? { items: items, olderCursor: String(n + 1), endReached: false } : { items: items, endReached: true };
}

async function searchProfiles(context, query, page) {
  var q = String(query || "").trim();
  if (!q) return { items: [], endReached: true };
  var offset = page.direction !== "refresh" && /^\d{1,6}$/.test(String(page.cursor || "")) ? Number(page.cursor) : 0;
  var limit = clamp(page.limit, 1, 40);
  var list = asArray((await authed(context, addQuery("/api/v1/accounts/search", {
    q: q, limit: String(limit), offset: String(offset), resolve: offset ? "false" : "true",
  }))).data).filter(function (a) { return a && a.id != null; });
  var items = list.map(function (a) { return mapProfile(a, context.origin); });
  return list.length >= limit ? { items: items, olderCursor: String(offset + list.length), endReached: false } : { items: items, endReached: true };
}

// Wafrn lets each address make one request per second to login, two-factor login and
// app registration combined, so sign-in steps are spaced out. The plugin sandbox has no
// timer; small host calls are used to let time pass.
var lastLimitedRequest = 0;

async function oncePerSecond(origin, path, options) {
  var ready = lastLimitedRequest + 1100;
  while (Date.now() < ready) {
    try { await flare.crypto.randomHex(1); } catch (_) { /* only waiting */ }
  }
  try {
    return await apiRequest(origin, path, options);
  } finally {
    lastLimitedRequest = Date.now();
  }
}

async function sendReaction(context, postKey, emojiName, undo) {
  var cred = (await flare.credential.read()) || {};
  if (!cred.jwt) unsupportedError("Reactions need the \"Sign in with email and password\" option; add the account again that way");
  var uuid = decodeId(postKey);
  if (!uuid) notFound("Unknown Wafrn post");
  if (!emojiName || emojiName.length > 512) validationError("Invalid reaction");
  var result = (await apiRequest(context.origin, "/api/emojiReact", {
    method: "POST",
    token: String(cred.jwt),
    body: { type: "json", value: { postId: uuid, emojiName: emojiName, undo: undo } },
  })).data || {};
  if (result.success !== true && !undo) validationError(remoteMessage(result, "Wafrn didn't accept this reaction"));
}

async function refreshedPost(context, postKey) {
  var status = (await authed(context, "/api/v1/statuses/" + encodeURIComponent(postKey))).data;
  var item = { type: "post", post: mapPost(status, context) };
  await enrichItems([item], context);
  return item.post;
}

/** Returns the reaction to send when a reply is only one emoji or one known :shortcode:. */
async function reactionFromText(context, text) {
  var value = String(text || "").trim();
  if (!value || value.length > 64) return null;
  var cred = (await flare.credential.read()) || {};
  if (!cred.jwt) return null;
  var shortcode = value.match(/^:([A-Za-z0-9_+-]+):$/);
  if (shortcode) {
    var known = (await customEmojis(context)).some(function (e) { return e.shortcode === shortcode[1]; });
    return known ? value : null;
  }
  var single;
  try {
    single = new RegExp("^(?:\\p{Regional_Indicator}{2}|\\p{Extended_Pictographic}[\\uFE0F\\p{Emoji_Modifier}]*(?:\\u200D\\p{Extended_Pictographic}[\\uFE0F\\p{Emoji_Modifier}]*)*|[0-9#*]\\uFE0F?\\u20E3)$", "u");
  } catch (_) {
    return null; // engine without Unicode property escapes: keep it a normal reply
  }
  return single.test(value) ? value : null;
}

// Wafrn's Mastodon API IDs are a 13-digit millisecond timestamp followed by the post
// UUID as a 39-digit decimal number. These convert without relying on BigInt.

function decodeId(id) {
  var s = String(id || "");
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return s.toLowerCase();
  var hex = null;
  if (/^[0-9]{13}[0-9a-f]{32}$/i.test(s) && /[a-f]/i.test(s.slice(13))) hex = s.slice(13).toLowerCase();
  else if (/^[0-9]{52}$/.test(s)) hex = decimalToHex(s.slice(13));
  else if (/^[0-9]{13}[0-9a-f]{32}$/i.test(s)) hex = s.slice(13).toLowerCase();
  if (!hex || hex.length > 32) return null;
  while (hex.length < 32) hex = "0" + hex;
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
}

function encodeId(uuid, createdAt) {
  var hex = String(uuid).replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  var ms = Date.parse(String(createdAt || ""));
  var stamp = String(Math.max(0, isNaN(ms) ? 0 : ms));
  while (stamp.length < 13) stamp = "0" + stamp;
  var dec = hexToDecimal(hex);
  while (dec.length < 39) dec = "0" + dec;
  return stamp + dec;
}

function decimalToHex(dec) {
  var digits = dec.replace(/^0+/, "").split("").map(Number);
  var out = "";
  while (digits.length) {
    var rest = [];
    var carry = 0;
    for (var i = 0; i < digits.length; i++) {
      var cur = carry * 10 + digits[i];
      var q = Math.floor(cur / 16);
      carry = cur % 16;
      if (rest.length || q) rest.push(q);
    }
    out = carry.toString(16) + out;
    digits = rest;
  }
  return out || "0";
}

function hexToDecimal(hex) {
  var digits = [0]; // little-endian base 10
  for (var i = 0; i < hex.length; i++) {
    var carry = parseInt(hex.charAt(i), 16);
    for (var j = 0; j < digits.length; j++) {
      var v = digits[j] * 16 + carry;
      digits[j] = v % 10;
      carry = Math.floor(v / 10);
    }
    while (carry) { digits.push(carry % 10); carry = Math.floor(carry / 10); }
  }
  return digits.reverse().join("").replace(/^0+(?=.)/, "");
}

// ----------------------------------------------------------------- mapping

function mapTimelineItem(status, context) {
  if (status && status.reblog) {
    return {
      type: "post",
      post: mapPost(status, context),
      presentation: { repost: mapPost(status.reblog, context) },
    };
  }
  return { type: "post", post: mapPost(status, context) };
}

function mapPost(status, context) {
  if (!status || status.id == null) invalidResponse("Wafrn returned an invalid post");
  var origin = context.origin;
  var host = originHost(origin);
  var post = {
    key: { id: String(status.id), host: host },
    createdAt: isoDate(status.created_at),
    content: { format: "html", value: emojify(askHtml(String(status.content || "")), mastodonEmojis(status.emojis, origin)) + tagsHtml(status) },
    media: mapMediaList(status.media_attachments, origin),
    sensitive: status.sensitive === true,
    visibility: fromWafrnVisibility(status.visibility),
    favouritesCount: count(status.favourites_count),
    repostsCount: count(status.reblogs_count),
    repliesCount: count(status.replies_count),
  };
  if (status.account) post.author = mapProfile(status.account, origin);
  if (!status.reblog) post.actions = postActions(status, context);
  var url = safeHttpsUrl(status.url || status.uri, origin);
  if (url) post.url = url;
  if (status.in_reply_to_id != null) post.replyTo = { id: String(status.in_reply_to_id), host: host };
  if (status.spoiler_text) post.spoilerText = String(status.spoiler_text);
  if (status.language) post.sourceLanguages = [String(status.language)];
  var card = mapCard(status.card, origin);
  if (card) post.card = card;
  return post;
}

function postActions(status, context) {
  var liked = status.favourited === true;
  var reblogged = status.reblogged === true;
  var actions = [
    { action: "Reply", count: count(status.replies_count) },
    { action: reblogged ? "Unrepost" : "Repost", active: reblogged, count: count(status.reblogs_count) },
    { action: liked ? "Unfavourite" : "Favourite", active: liked, count: count(status.favourites_count) },
  ];
  if (isOwnPost(status, context)) actions.push({ action: "Delete" });
  return actions;
}

function isOwnPost(status, context) {
  return !!(context && status && status.account && status.account.id != null &&
    String(status.account.id) === String(context.accountId));
}

// Asks: Wafrn's Mastodon API starts an answered ask with "<p><b>Name</b> asked: question</p>".
// Shown like Tumblr asks instead: the question in a quote box, then the answer.
function askHtml(content) {
  var m = /^\s*<p><b>([^<]*)<\/b> asked: ([\s\S]*?)<\/p>/.exec(content);
  if (!m) return content;
  return askBox(m[1], m[2]) + content.slice(m[0].length);
}

/** Builds the ask box; name and question arrive already escaped. */
function askBox(name, question) {
  var lines = String(question).trim().split(/\n+/).filter(Boolean);
  return "<blockquote><p><b>" + (name || "Anonymous") + "</b> asked:</p>" +
    (lines.length ? lines.map(function (l) { return "<p>" + l + "</p>"; }).join("") : "") + "</blockquote>";
}

/** The ask box for a post from Wafrn's own API (quoted posts), from its asks list. */
function nativeAskHtml(p, data) {
  var ask = asArray(data && data.asks).filter(function (a) { return a && a.postId === p.id; })[0];
  if (!ask) return "";
  var asker = ask.userAsker ? asArray(data.users).filter(function (u) { return u && u.id === ask.userAsker; })[0] : null;
  return askBox(esc(asker ? String(asker.name || asker.url || "Anonymous") : "Anonymous"), esc(String(ask.question || "")));
}

function tagsHtml(status) {
  var tags = asArray(status.tags).filter(function (t) { return t && t.name; });
  if (!tags.length) return "";
  // Wafrn tags are Tumblr-style and usually not part of the body text.
  var body = String(status.content || "").toLowerCase();
  var missing = tags.filter(function (t) { return body.indexOf("#" + String(t.name).toLowerCase()) < 0; });
  if (!missing.length) return "";
  return "<p>" + missing.map(function (t) {
    var url = safeHttpsUrl(t.url, null);
    var label = "#" + esc(String(t.name));
    return url ? '<a href="' + esc(url) + '">' + label + "</a>" : label;
  }).join(" ") + "</p>";
}

function mapCard(card, origin) {
  if (!card || !card.url) return null;
  var url = safeHttpsUrl(card.url, origin);
  if (!url) return null;
  var result = { title: String(card.title || card.url), url: url };
  if (card.description) result.description = String(card.description);
  return result;
}

function mapProfile(account, origin) {
  if (!account || account.id == null) invalidResponse("Wafrn returned an invalid profile");
  var host = originHost(origin);
  var acct = String(account.acct || account.username || account.id).replace(/^@/, "");
  var profile = {
    key: { id: String(account.id), host: host },
    handle: "@" + (acct.indexOf("@") >= 0 ? acct : acct + "@" + host),
    displayName: String(account.display_name || account.username || acct),
    description: { format: "html", value: emojify(String(account.note || ""), mastodonEmojis(account.emojis, origin)) },
    followersCount: count(account.followers_count),
    followingCount: count(account.following_count),
    postsCount: count(account.statuses_count),
    locked: account.locked === true,
    bot: account.bot === true,
  };
  var avatar = safeHttpsUrl(account.avatar_static || account.avatar, origin);
  var banner = safeHttpsUrl(account.header_static || account.header, origin);
  var url = safeHttpsUrl(account.url, origin);
  if (avatar) profile.avatarUrl = avatar;
  if (banner) profile.bannerUrl = banner;
  if (url) profile.url = url;
  var fields = asArray(account.fields).slice(0, 32).filter(function (f) { return f && f.name; });
  if (fields.length) {
    profile.fields = fields.map(function (f) {
      return { name: String(f.name), value: { format: "html", value: String(f.value || "") } };
    });
  }
  return profile;
}

function mapRelation(rel, key) {
  if (!rel || typeof rel !== "object") invalidResponse("Wafrn returned an invalid relationship");
  return {
    profileKey: { id: key.id, host: key.host },
    following: rel.following === true || rel.requested === true,
    followedBy: rel.followed_by === true,
    blocking: rel.blocking === true,
    muting: rel.muting === true,
  };
}

function mapNotification(n, context) {
  if (!n || n.id == null) return null;
  var host = originHost(context.origin);
  var actor = n.account ? mapProfile(n.account, context.origin) : undefined;
  var createdAt = isoDate(n.created_at);
  var message = { key: { id: "n" + String(n.id), host: host }, createdAt: createdAt };
  if (actor) message.actor = actor;
  var kind = {
    mention: "Mention",
    status: "NewPost",
    reblog: "Repost",
    follow: "Follow",
    follow_request: "FollowRequest",
    favourite: "Favourite",
    "pleroma:emoji_reaction": "Reaction",
    "wafrn:quote": "Quote",
  }[n.type];
  if (kind) {
    message.kind = kind;
    if (kind === "Reaction" && n.emoji) message.args = [String(n.emoji)];
  } else if (n.type === "bite") {
    message.text = "bit you";
  } else if (n.type === "wafrn:ask") {
    message.text = "sent you an ask";
  } else {
    message.unknownType = String(n.type || "unknown");
  }
  if (n.status) {
    var item = mapTimelineItem(n.status, context);
    var presentation = item.presentation || {};
    presentation.message = message;
    presentation.notificationKey = { id: "n" + String(n.id), host: host };
    return { type: "post", post: item.post, presentation: presentation };
  }
  if (actor) message.target = { type: "profile", key: actor.key };
  return { type: "message", message: message };
}

function mapMediaList(values, origin) {
  return asArray(values).map(function (m) { return mapMedia(m, origin); }).filter(Boolean).slice(0, 100);
}

function mapMedia(media, origin) {
  if (!media || media.id == null) return null;
  var url = safeHttpsUrl(media.url || media.remote_url, origin);
  if (!url) return null;
  var type = String(media.type || "");
  if (type === "gifv") type = "gif";
  if (["image", "video", "gif", "audio"].indexOf(type) < 0) return null;
  var result = { id: String(media.id), type: type, url: url };
  var preview = safeHttpsUrl(media.preview_url, origin);
  if (preview && type !== "audio") result.previewUrl = preview;
  if (media.description) result.description = String(media.description);
  var original = (media.meta && media.meta.original) || {};
  if (positive(original.width)) result.width = Math.round(original.width);
  if (positive(original.height)) result.height = Math.round(original.height);
  if (positive(original.duration)) result.durationMillis = Math.round(original.duration * 1000);
  return result;
}

function mapInstance(instance, origin) {
  var result = { domain: originHost(origin) };
  if (instance && instance.title) result.title = String(instance.title);
  if (instance && instance.description) result.description = String(instance.description);
  var thumb = instance && instance.thumbnail && safeHttpsUrl(instance.thumbnail.url, origin);
  // Flare rejects (and then hides) detections whose icon is on another site.
  if (thumb && thumb.indexOf(requireOrigin(origin) + "/") === 0) result.iconUrl = thumb;
  var reg = instance && instance.registrations;
  if (reg && typeof reg === "object") result.registrationEnabled = reg.enabled === true;
  return result;
}

function composeConfig(instance) {
  var conf = (instance && instance.configuration) || {};
  var statuses = conf.statuses || {};
  var media = conf.media_attachments || {};
  var mimes = asArray(media.supported_mime_types).filter(validMimeType).slice(0, 128);
  var maxBytes = Math.min(
    positive(media.image_size_limit) ? media.image_size_limit : 8 * 1024 * 1024,
    positive(media.video_size_limit) ? media.video_size_limit : 8 * 1024 * 1024,
    1073741824,
  );
  return {
    text: { maxLength: Math.round(clamp(statuses.max_characters || 5000, 1, 1000000)) },
    media: {
      maxCount: Math.round(clamp(statuses.max_media_attachments || 4, 0, 100)),
      maxBytes: Math.round(maxBytes),
      supportedMimeTypes: mimes.length ? mimes : ["image/jpeg", "image/png", "image/gif", "image/webp"],
      altTextMaxLength: 1500,
      canSensitive: false,
    },
    visibility: { allowed: ["public", "unlisted", "followers", "direct"], default: "public" },
    contentWarning: true,
  };
}

function isWafrn(instance) {
  if (!instance || typeof instance !== "object") return false;
  return [instance.version, instance.source_url].some(function (v) {
    return String(v || "").toLowerCase().indexOf("wafrn") >= 0;
  });
}

function fromWafrnVisibility(value) {
  if (value === "unlisted") return "unlisted";
  if (value === "private") return "followers";
  if (value === "direct") return "direct";
  if (value === "public") return "public";
  return null;
}

function toWafrnVisibility(value) {
  if (value === "followers") return "private";
  if (value === "unlisted") return "unlisted";
  if (value === "direct") return "direct";
  return "public";
}

// ------------------------------------------------------------------- HTTP

async function authed(context, path, options) {
  var credential = await flare.credential.read();
  if (!credential || typeof credential !== "object" || !credential.accessToken) {
    authenticationError();
  }
  return apiRequest(context.origin, path, Object.assign({}, options || {}, { token: String(credential.accessToken) }));
}

async function apiRequest(origin, path, options) {
  var opts = options || {};
  var request = {
    method: opts.method || "GET",
    url: /^https:\/\//i.test(path) ? path : requireOrigin(origin) + path,
    headers: { Accept: "application/json" },
  };
  if (opts.token) request.authorization = { type: "bearer", token: opts.token };
  if (opts.body) request.body = opts.body;
  if (opts.timeoutMillis) request.timeoutMillis = opts.timeoutMillis;
  var response;
  try {
    if (!request.timeoutMillis) request.timeoutMillis = REQUEST_TIMEOUT_MS;
    response = await flare.http.request(request);
  } catch (error) {
    if (!(error && error.__flarePluginErrorV1 !== undefined)) {
      fail("Network", "Could not reach the Wafrn server");
    }
    throw error;
  }
  var data = parseBody(response);
  var status = response.status;
  if (status >= 200 && status < 300) return { status: status, data: data, headers: response.headers || {} };
  if (status === 401 || status === 403) authenticationError();
  if (status === 404) notFound("The requested Wafrn content was not found");
  if (status === 422 || status === 400) validationError(remoteMessage(data, "Wafrn rejected the request"));
  if (status === 429) {
    var error = { code: "RateLimited", message: { value: "Wafrn is rate limiting requests" } };
    var wait = retryAfter(response.headers);
    if (wait !== undefined) error.retryAfterSeconds = wait;
    throw flare.error(error);
  }
  fail("Remote", remoteMessage(data, "Wafrn returned HTTP " + status));
}

function parseBody(response) {
  var body = typeof response.body === "string" ? response.body.trim() : "";
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch (_) {
    if (response.status >= 200 && response.status < 300) invalidResponse("Wafrn did not return JSON");
    return null;
  }
}

function retryAfter(headers) {
  var value = header(headers, "retry-after");
  var n = Number(value);
  return value != null && Number.isFinite(n) && n >= 0 ? Math.min(604800, Math.round(n)) : undefined;
}

function header(headers, name) {
  var keys = Object.keys(headers || {});
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === name) {
      var v = headers[keys[i]];
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return undefined;
}

function remoteMessage(data, fallback) {
  var v = data && (data.error_description || data.error || data.message);
  return typeof v === "string" && v.trim() ? v.slice(0, 500) : fallback;
}

// ---------------------------------------------------------------- helpers

function fail(code, message) {
  throw flare.error({ code: code, message: { value: message } });
}
function authenticationError() { fail("AuthenticationRequired", "Sign in to Wafrn again"); }
function validationError(message) { fail("Validation", message); }
function invalidResponse(message) { fail("InvalidResponse", message); }
function unsupportedError(message) { fail("Unsupported", message); }
function notFound(message) { fail("NotFound", message); }

function requiredString(value, message) {
  if (value == null || String(value).trim() === "") validationError(message);
  return String(value);
}

function requireOrigin(value) {
  var origin = String(value || "").trim().replace(/\/+$/, "");
  if (!/^https:\/\/[^/?#@]+$/i.test(origin)) validationError("Enter the HTTPS address of your Wafrn server");
  return origin;
}

function originHost(origin) {
  return requireOrigin(origin).slice(8).toLowerCase();
}

function safeHttpsUrl(value, origin) {
  if (value == null) return null;
  var text = String(value).trim();
  if (!text) return null;
  if (text.charAt(0) === "/" && text.charAt(1) !== "/" && origin) text = requireOrigin(origin) + text;
  return /^https:\/\/[^/?#@\s]+(?:[/?#][^\s]*)?$/i.test(text) ? text : null;
}

function addQuery(path, values) {
  var pairs = [];
  Object.keys(values || {}).forEach(function (key) {
    var raw = values[key];
    if (raw == null || raw === "") return;
    (Array.isArray(raw) ? raw : [raw]).forEach(function (item) {
      pairs.push(encodeURIComponent(key) + "=" + encodeURIComponent(String(item)));
    });
  });
  if (!pairs.length) return path;
  return path + (path.indexOf("?") >= 0 ? "&" : "?") + pairs.join("&");
}

function esc(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function isoDate(value) {
  var d = new Date(String(value || ""));
  return isNaN(d.getTime()) ? new Date(0).toISOString() : d.toISOString();
}

function asArray(value) { return Array.isArray(value) ? value : []; }
function positive(value) { return typeof value === "number" && Number.isFinite(value) && value > 0; }
function count(value) {
  var n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
}
function clamp(value, min, max) {
  var n = Number(value);
  if (!Number.isFinite(n)) n = min;
  return Math.min(max, Math.max(min, n));
}
function validMimeType(value) {
  return typeof value === "string" && /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+*-]+$/.test(value);
}

// Adds an "Open in <site>" link to the end of a post when it's opened on its own
// (detail and thread views), since plugins can't add items to Flare's post menu.
function withOpenLinks(label, definition, urlFor) {
  var post = definition.capabilities && definition.capabilities.post;
  if (!post) return definition;
  function addLink(p, context) {
    if (!p || !p.content || p.content.format !== "html") return p;
    var url = urlFor ? urlFor(p, context) : p.url;
    if (!url || !/^https:\/\//i.test(url)) return p;
    var link = '<p><a href="' + String(url).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;") +
      '">Open in ' + label + " \u2197</a></p>";
    return Object.assign({}, p, { content: { format: "html", value: p.content.value + link } });
  }
  var detail = post.detail;
  if (detail) {
    post.detail = async function (request, context) {
      var result = await detail.call(this, request, context);
      if (result && result.post && (!result.presentation || !result.presentation.repost)) {
        result = Object.assign({}, result, { post: addLink(result.post, context) });
      }
      return result;
    };
  }
  var thread = post.context;
  if (thread) {
    post.context = async function (request, context) {
      var result = await thread.call(this, request, context);
      if (result && Array.isArray(result.items)) {
        var done = false;
        var handles = {};
        result.items.forEach(function (item) {
          if (item && item.post && item.post.key && item.post.author) handles[item.post.key.id] = item.post.author.handle;
        });
        result = Object.assign({}, result, { items: result.items.map(function (item) {
          if (!item || item.type !== "post" || !item.post || !item.post.key) return item;
          if (done) {
            // Flare redraws a reply's parent above it when both are in the list, which
            // repeats the opened post (or a busy comment) over every reply. Replies below
            // the opened post are listed plainly, labelled with who they answer.
            if (!item.post.replyTo) return item;
            var flat = Object.assign({}, item.post);
            var to = handles[flat.replyTo.id];
            delete flat.replyTo;
            if (to && !flat.replyToHandle) flat.replyToHandle = to;
            return Object.assign({}, item, { post: flat });
          }
          if (item.post.key.id !== request.key.id) return item;
          done = true;
          if (item.presentation && item.presentation.repost) return item;
          return Object.assign({}, item, { post: addLink(item.post, context) });
        }) });
      }
      return result;
    };
  }
  return definition;
}

// "Open in Wafrn" goes to the post on your Wafrn server, also for posts from elsewhere.
function wafrnPageUrl(post, context) {
  if (/^emoji:/.test(post.key.id)) return null;
  var uuid = decodeId(post.key.id);
  return uuid ? requireOrigin(context.origin) + "/fediverse/post/" + encodeURIComponent(uuid) : post.url;
}
