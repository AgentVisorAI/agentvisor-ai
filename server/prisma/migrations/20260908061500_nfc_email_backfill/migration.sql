-- Round-116 (R14 hunt): #381 NFC-normalizes emails at every ENTRY
-- point but left pre-existing rows in whatever byte form they were
-- created with. Any user whose stored email is non-NFC (macOS NFD
-- input paths) became unreachable the moment #381 deployed: every
-- lookup now normalizes to NFC, misses the NFD row, login burns the
-- timing dummy and answers "wrong password", reset-request mails
-- nobody, and a fresh signup with the same visual address mints a
-- SHADOW DUPLICATE account. Backfill existing rows to NFC.
--
-- Collision guard: if both byte forms already exist as separate rows
-- (the pre-#381 drill scenario), rewriting one would trip the unique
-- constraint and abort the deploy. Those rows are left untouched —
-- they are genuine duplicate accounts only an operator can merge; the
-- NFC copy keeps working, which is strictly no worse than before.
--
-- normalize(..., NFC) requires Postgres 13+ (the repo's floor is 16).
UPDATE "users" u
SET "email" = normalize(u."email", NFC)
WHERE u."email" <> normalize(u."email", NFC)
  AND NOT EXISTS (
    SELECT 1 FROM "users" v WHERE v."email" = normalize(u."email", NFC)
  );

-- Invites are matched by (orgId, email) at accept time with the same
-- now-NFC entry normalization — un-normalized pending invites became
-- unacceptable ("invite_not_found") the same way.
UPDATE "invites" i
SET "email" = normalize(i."email", NFC)
WHERE i."email" <> normalize(i."email", NFC)
  AND NOT EXISTS (
    SELECT 1
    FROM "invites" w
    WHERE w."orgId" = i."orgId"
      AND w."email" = normalize(i."email", NFC)
  );
