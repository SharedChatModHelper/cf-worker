export default {
  async fetch(request, env, ctx) {
    const auth = request.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
      return new Response();
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
      }
    } else if (request.method === "GET") {
      const channelId = new URL(request.url).searchParams.get("channel");
      if (channelId) {
        const modId = await verifyToken(env, token);
        if (modId && await isMod(env, channelId, modId, token)) {
          const resp = await getBannedMessages(db, channelId);
          return new Response(JSON.stringify(resp));
        }
      }
    } else if (request.method === "DELETE") {
      const url = new URL(request.url);
      const channelId = url.searchParams.get("channel");
      const userId = url.searchParams.get("user");
      if (channelId && userId) {
        const modId = await verifyToken(env, token);
        if (modId && await isMod(env, channelId, modId, token)) {
          await deleteBannedMessages(db, channelId, userId);
        }
      }
    }

    return new Response();
  },
};

function verify(actual, expected) {
  const encoder = new TextEncoder();
  const a = encoder.encode(actual);
  const b = encoder.encode(expected);
  return a.length === b.length && crypto.subtle.timingSafeEqual(a, b);
}

async function verifyToken(env, token) {
  const resp = await fetch("https://id.twitch.tv/oauth2/validate", {
    method: "GET",
    headers: {
      "Authorization": "OAuth " + token
    }
  });
  const body = await resp.json();
  if (body["client_id"] != env["CLIENT_ID"]) return null;
  return body["user_id"];
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

async function handleBannedMessages(db, data) {
  await db.prepare("INSERT INTO bans (channel_id, user_id, mod_id, mod_login, source_room_id, source_room_login, timestamp, duration, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)")
          .bind(data.channelId, data.userId, data.moderatorId, data.moderatorLogin, data.sourceRoomId, data.sourceRoomLogin, data.timestamp, data.duration, data.reason)
          .run();

  const stmt = db.prepare("INSERT INTO banned_messages (channel, user, username, room_id, room_login, ts, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)");
  await db.batch(data.messages.map((msg) => stmt.bind(data.channelId, data.userId, data.userLogin, msg.sourceId ?? "", msg.sourceLogin ?? "", msg.ts ?? "", msg.text)));
}

async function getBannedMessages(db, channel) {
  const query = db.prepare("SELECT * FROM (bans LEFT JOIN banned_messages ON bans.channel_id = banned_messages.channel AND bans.user_id = banned_messages.user) WHERE bans.channel_id = ?1 ORDER BY bans.timestamp DESC, banned_messages.ts LIMIT 25").bind(channel);
  const { results } = await query.all();

  const map = new Map();
  for (const row of results) {
    let obj = map.get(row["user_id"]);
    if (!obj) {
      obj = {
        userId: row["user_id"],
        userLogin: row["user_login"],
        userName: row["user_name"],
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
      obj.messages.push({text: row["message"], sourceId: row["room_id"], sourceLogin: row["room_login"], timestamp: row["ts"]});
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
