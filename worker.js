export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "DELETE,GET,POST,OPTIONS",
          "Access-Control-Max-Age": "86400",
          "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") ?? "Accept, Authorization, Content-Type, Origin",
          "Allow": "DELETE, GET, POST, OPTIONS",
        }
      });
    }

    const auth = request.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
      return makeErrorResponse(401, "Missing auth");
    }
    const token = auth.substring("Bearer ".length);

    const db = env.d1;
    if (request.method === "POST") {
      if (verify(token, env["CLIENT_DB_TOKEN"])) {
        const body = await request.json();
        if (body.duration === 0) {
          // unban or untimeout
          await deleteBannedMessages(db, body.channelId, body.userId);
        } else {
          // ban or timeout
          await handleBannedMessages(db, body);
        }
        return new Response(null, { status: 204 });
      } else {
        return makeErrorResponse(403, "Invalid auth");
      }
    } else if (request.method === "GET") {
      const channelId = new URL(request.url).searchParams.get("channel");
      if (channelId) {
        const { modId, scopes } = await verifyToken(env, token);
        if (!modId) {
          return makeErrorResponse(403, "Invalid auth");
        }
        if (!scopes.includes("moderator:read:shield_mode")) {
          return makeErrorResponse(403, "Invalid scopes");
        }
        if (await isMod(env, channelId, modId, token)) {
          const resp = await getBannedMessages(db, channelId);
          return Response.json(resp, {
            headers: {
              "Access-Control-Allow-Origin": "*",
            }
          });
        } else {
          return makeErrorResponse(403, "Insufficient auth");
        }
      } else {
        const { modId, scopes } = await verifyToken(env, token);
        if (modId) {
          if (!scopes.includes("user:read:moderated_channels")) {
            return makeErrorResponse(403, "Invalid scopes");
          }
          const channels = await getModChannels(env, modId, token);
          if (!channels) {
            return Response.json([]);
          }
          const { results } = await db.prepare("SELECT channel_id, channel_name, image_url FROM auths WHERE authorized_at > 0 AND channel_id IN (" + channels.join(",") + ")").all();
          return Response.json(results, {
            headers: {
              "Access-Control-Allow-Origin": "*",
            }
          });
        } else {
          return makeErrorResponse(403, "Invalid auth");
        }
      }
    } else if (request.method === "DELETE") {
      const url = new URL(request.url);
      const channelId = url.searchParams.get("channel");
      const userId = url.searchParams.get("user");
      if (channelId && userId) {
        const { modId, scopes } = await verifyToken(env, token);
        if (!modId) {
          return makeErrorResponse(403, "Invalid auth");
        }
        if (!scopes.includes("moderator:read:shield_mode")) {
          return makeErrorResponse(403, "Invalid scopes");
        }
        if (await isMod(env, channelId, modId, token)) {
          await deleteBannedMessages(db, channelId, userId);
          return new Response(null, {
            status: 204,
            headers: {
              "Access-Control-Allow-Origin": "*",
            }
          });
        } else {
          return makeErrorResponse(403, "Insufficient auth");
        }
      } else {
        return makeErrorResponse(400, "Invalid request");
      }
    } else if (request.method == "PUT") {
      if (verify(token, env["CLIENT_DB_TOKEN"])) {
        const body = await request.json();
        const authAt = body.added ? body.timestamp : 0;
        const revokeAt = body.added ? 0 : body.timestamp;
        await db.prepare("REPLACE INTO auths (channel_id, channel_name, authorized_at, revoked_at, image_url) VALUES (?1, ?2, ?3, ?4, ?5)")
                .bind(body.channelId, body.channelName, authAt, revokeAt, body.imageUrl ?? "")
                .run();
        return new Response(null, { status: 204 });
      } else {
        return makeErrorResponse(403, "Invalid auth");
      }
    }

    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
      }
    });
  },
};

function makeErrorResponse(code, message) {
  return new Response(JSON.stringify({ error: message }), { 
    status: code, 
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json"
    } 
  });
}

function verify(actual, expected) {
  const encoder = new TextEncoder();
  const a = encoder.encode(actual);
  const b = encoder.encode(expected);
  return a.length === b.length && crypto.subtle.timingSafeEqual(a, b);
}

async function verifyToken(env, token) {
  let body;
  try {
    const resp = await fetch("https://id.twitch.tv/oauth2/validate", {
      method: "GET",
      headers: {
        "Authorization": "OAuth " + token
      }
    });
    body = await resp.json();
  } catch (error) {
    body = {};
  }
  if (body["client_id"] != env["CLIENT_ID"]) return { modId: null, scopes: [] };
  return {
    modId: body["user_id"],
    scopes: body["scopes"] ?? []
  };
}

async function isMod(env, channel, user, token) {
  const resp = await fetch("https://api.twitch.tv/helix/moderation/shield_mode?broadcaster_id=" + channel + "&moderator_id=" + user, {
    method: "GET",
    headers: {
      "Client-Id": env["CLIENT_ID"],
      "Authorization": "Bearer " + token
    }
  });
  const body = await resp.json();
  return !!body["data"];
}

async function getModChannels(env, user, token) {
  const channels = new Set();
  let cursor = "";
  do {
    const resp = await fetch("https://api.twitch.tv/helix/moderation/channels?first=100&user_id=" + user + "&after=" + cursor, {
      method: "GET",
      headers: {
        "Client-Id": env["CLIENT_ID"],
        "Authorization": "Bearer " + token
      }
    });
    const body = await resp.json();
    if (body.data) {
      body.data.forEach((chan) => {
        channels.add(chan["broadcaster_id"]);
      });
    }
    cursor = body.pagination ? body.pagination.cursor : null;
  } while (cursor && channels.size < 1000);
  return Array.from(channels);
}

async function handleBannedMessages(db, data) {
  await db.prepare("INSERT INTO bans (channel_id, user_id, mod_id, mod_login, source_room_id, source_room_login, timestamp, duration, reason, user_login) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")
          .bind(data.channelId, data.userId, data.moderatorId, data.moderatorLogin, data.sourceRoomId, data.sourceRoomLogin, data.timestamp, data.duration, data.reason, data.userLogin)
          .run();

  const stmt = db.prepare("INSERT INTO banned_messages (channel, user, username, room_id, room_login, ts, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)");
  await db.batch(data.messages.map((msg) => stmt.bind(data.channelId, data.userId, data.userLogin, msg.sourceId ?? "", msg.sourceLogin ?? "", msg.ts ?? "", msg.text)));
}

async function getBannedMessages(db, channel) {
  const query = db.prepare("SELECT * FROM (bans LEFT JOIN banned_messages ON bans.channel_id = banned_messages.channel AND bans.user_id = banned_messages.user) WHERE bans.channel_id = ?1 ORDER BY bans.timestamp DESC, banned_messages.ts LIMIT 250").bind(channel);
  const { results } = await query.all();

  const map = new Map();
  for (const row of results) {
    let obj = map.get(row["user_id"]);
    if (!obj) {
      obj = {
        userId: row["user_id"],
        userName: row["username"] ?? row["user_login"],
        modId: row["mod_id"],
        modLogin: row["mod_login"],
        sourceId: row["source_room_id"],
        sourceLogin: row["source_room_login"],
        duration: row["duration"],
        reason: row["reason"],
        timestamp: row["timestamp"],
        messages: []
      };
      map.set(row["user_id"], obj);
    }

    if (row.message) {
      const roomId = row["room_id"] ?? "";
      const roomLogin = row["room_login"] ?? "";
      obj.messages.push({
        text: row["message"],
        sourceId: roomId ? roomId : row["source_room_id"],
        sourceLogin: roomLogin ? roomLogin : row["source_room_login"],
        timestamp: row["ts"],
      });
    }
  }

  return Array.from(map.values());
}

async function deleteBannedMessages(db, channel, user) {
  await db.batch([
    db.prepare("DELETE FROM bans WHERE channel_id = ?1 AND user_id = ?2").bind(channel, user),
    db.prepare("DELETE FROM banned_messages WHERE channel = ?1 AND user = ?2").bind(channel, user),
  ]);
}
