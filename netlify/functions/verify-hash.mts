import type { Config } from "@netlify/functions";
import { eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import { authenticHashes } from "../../db/schema.js";

export default async (req: Request) => {
  let hash: unknown;
  try {
    ({ hash } = await req.json());
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (typeof hash !== "string" || !/^[a-f0-9]{64}$/i.test(hash)) {
    return Response.json({ error: "Expected a SHA-256 hex digest in `hash`" }, { status: 400 });
  }

  const [match] = await db
    .select({ fileName: authenticHashes.fileName })
    .from(authenticHashes)
    .where(eq(authenticHashes.hashValue, hash.toLowerCase()))
    .limit(1);

  return Response.json({ verified: Boolean(match), fileName: match?.fileName ?? null });
};

export const config: Config = {
  path: "/api/verify-hash",
  method: "POST",
};
