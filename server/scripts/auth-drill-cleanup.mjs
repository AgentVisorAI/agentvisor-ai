// A stalled graceful PostgreSQL close must not prevent owned-resource cleanup.
export async function closeDrillClient(client, timeoutMs = 2000) {
  let timer;
  try {
    await Promise.race([client.end(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("database close timed out")), timeoutMs);
    })]);
  } catch (error) {
    client.connection?.stream?.destroy();
    throw error;
  } finally { clearTimeout(timer); }
}
