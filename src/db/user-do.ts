import { DurableObject } from "cloudflare:workers";
import { drizzle, DrizzleSqliteDODatabase } from "drizzle-orm/durable-sqlite";
import { migrate } from "drizzle-orm/durable-sqlite/migrator";
import migrations from "./migrations/migrations";
import * as schema from "./schema";

export class UserDurableObject extends DurableObject {
  db: DrizzleSqliteDODatabase<typeof schema>;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = drizzle(ctx.storage, { schema });

    ctx.blockConcurrencyWhile(async () => {
      await migrate(this.db, migrations);
    });
  }

  async getToken() {
    const result = await this.db.select().from(schema.openrouter).limit(1);
    return result[0] ?? null;
  }

  async hasToken() {
    const result = await this.db.select({ id: schema.openrouter.id }).from(schema.openrouter).limit(1);
    return result.length > 0;
  }

  async setToken(accessToken: string, balance: number = -1) {
    await this.db.delete(schema.openrouter);
    await this.db.insert(schema.openrouter).values({
      id: 1,
      accessToken,
      balance,
    });
  }

  async updateBalance(balance: number) {
    await this.db.update(schema.openrouter).set({ balance });
  }

  async deleteToken() {
    await this.db.delete(schema.openrouter);
  }
}
