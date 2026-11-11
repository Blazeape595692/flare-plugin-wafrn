// Wafrn adapter for Flare Social Plugin API v1.
//
// Wafrn (https://codeberg.org/wafrn/wafrn) is a Tumblr-inspired fediverse/Bluesky
// server. This plugin talks to its Mastodon-compatible API (/api/v1, /oauth), which
// supports dynamic OAuth app registration, so signing in happens in the browser and
// Flare never sees the password.
//
// Not exposed because Wafrn's Mastodon API does not provide them yet: search,
// deleting posts, bookmarks, block/mute, polls, follower/following lists.

var WAFRN_CAPABILITIES = {
  "flare.datasource.timeline/v1": ["page"],
  "flare.datasource.profile/v1": ["byId", "byHandle", "timeline"],
  "flare.datasource.post/v1": ["detail", "context", "mutate"],
  "flare.datasource.relation/v1": ["state", "mutate"],
  "flare.datasource.notification/v1": ["page", "badge"],
  "flare.datasource.compose/v1": ["publish"],
};

var OAUTH_SCOPES = "read write follow";

var NOTIFICATION_TYPES = {
  mention: ["mention"],
  like: ["favourite", "pleroma:emoji_reaction"],
};

defineFlareSocialPlugin({
  detector: {
    async detect(request, context) {
      var origin = requireOrigin(request.origin || context.origin);
      var instance;
      try {
        instance = (await apiRequest(origin, "/api/v2/instance")).data;
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
  },

  capabilities: {
    timeline: {
      async page(request, context) {
        var id = request.timelineId;
        if (id === "home") return statusPage(context, "/api/v1/timelines/home", request.page, {});
        if (id === "local") return statusPage(context, "/api/v1/timelines/public", request.page, { local: "true" });
        if (id === "explore") return statusPage(context, "/api/v1/timelines/public", request.page, {});
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
        var status = (await authed(context, "/api/v1/statuses/" + encodeURIComponent(request.key.id))).data;
        var item = mapTimelineItem(status, context);
        return item.presentation ? { post: item.post, presentation: item.presentation } : { post: item.post };
      },
      async context(request, context) {
        var id = encodeURIComponent(request.key.id);
        var detail = (await authed(context, "/api/v1/statuses/" + id)).data;
        var thread = (await authed(context, "/api/v1/statuses/" + id + "/context")).data || {};
        var values = [];
        asArray(thread.ancestors).forEach(function (s) { values.push(s); });
        values.push(detail);
        asArray(thread.descendants).forEach(function (s) { values.push(s); });
        return {
          items: values.filter(Boolean).slice(0, 200).map(function (s) { return mapTimelineItem(s, context); }),
          endReached: true,
        };
      },
      async mutate(request, context) {
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
        return { type: "updatedPost", post: mapPost(status, context) };
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
        values.forEach(function (n) {
          var item = mapNotification(n, context);
          if (item) items.push(item);
        });
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
        return { post: mapPost(response.data, context) };
      },
    },
  },
});

// ------------------------------------------------------------------ paging

async function statusPage(context, path, page, params) {
  var query = Object.assign({}, params, { limit: String(clamp(page.limit, 1, 40)) });
  if (page.direction !== "refresh" && page.cursor) query.max_id = page.cursor;
  var values = asArray((await authed(context, addQuery(path, query))).data);
  var items = values.filter(Boolean).map(function (s) { return mapTimelineItem(s, context); });
  var last = values[values.length - 1];
  // Wafrn's Link header may report http:// behind proxies, so page by the last ID.
  if (!last || last.id == null) return { items: items, endReached: true };
  return { items: items, olderCursor: String(last.id), endReached: false };
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
    content: { format: "html", value: String(status.content || "") + tagsHtml(status) },
    media: mapMediaList(status.media_attachments, origin),
    sensitive: status.sensitive === true,
    visibility: fromWafrnVisibility(status.visibility),
    favouritesCount: count(status.favourites_count),
    repostsCount: count(status.reblogs_count),
    repliesCount: count(status.replies_count),
  };
  if (status.account) post.author = mapProfile(status.account, origin);
  if (!status.reblog) post.actions = postActions(status);
  var url = safeHttpsUrl(status.url || status.uri, origin);
  if (url) post.url = url;
  if (status.in_reply_to_id != null) post.replyTo = { id: String(status.in_reply_to_id), host: host };
  if (status.spoiler_text) post.spoilerText = String(status.spoiler_text);
  if (status.language) post.sourceLanguages = [String(status.language)];
  var card = mapCard(status.card, origin);
  if (card) post.card = card;
  return post;
}

function postActions(status) {
  var liked = status.favourited === true;
  var reblogged = status.reblogged === true;
  return [
    { action: "Reply", count: count(status.replies_count) },
    { action: reblogged ? "Unrepost" : "Repost", active: reblogged, count: count(status.reblogs_count) },
    { action: liked ? "Unfavourite" : "Favourite", active: liked, count: count(status.favourites_count) },
  ];
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
    description: { format: "html", value: String(account.note || "") },
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
    response = await flare.http.request(request);
  } catch (error) {
    if (error && typeof error === "object" && error.code === "host.unavailable") {
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
