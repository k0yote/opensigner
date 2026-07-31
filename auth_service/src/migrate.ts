import { getMigrations } from "better-auth/db/migration";
import { auth, databasePool } from "./server";

async function migrate(): Promise<void> {
  const { runMigrations, toBeAdded, toBeCreated } = await getMigrations(auth.options);

  if (toBeCreated.length === 0 && toBeAdded.length === 0) {
    console.log("Better Auth schema is already up to date");
    return;
  }

  await runMigrations();
  console.log(
    `Better Auth migration complete: ${toBeCreated.length} table(s) created, ` +
      `${toBeAdded.length} table(s) altered`,
  );
}

void migrate()
  .catch((error: unknown) => {
    console.error("Better Auth migration failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await databasePool.end();
  });
