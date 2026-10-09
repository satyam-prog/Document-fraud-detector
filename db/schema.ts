import { pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

export const authenticHashes = pgTable("authentic_hashes", {
  id: serial().primaryKey(),
  fileName: text("file_name").notNull(),
  hashValue: text("hash_value").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow(),
});
