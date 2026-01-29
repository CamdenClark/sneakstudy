import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";

export const openrouter = sqliteTable("openrouter", {
  id: integer("id").primaryKey(),
  accessToken: text("access_token").notNull(),
  balance: integer("balance").default(-1),
});
