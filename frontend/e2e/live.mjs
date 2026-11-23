// Live end-to-end walk-through against a running stack (backend on :8000 via the
// Vite proxy on :5173). Not part of `npm test`; run with:
//
//   ZT_ADMIN_USER=... ZT_ADMIN_PASSWORD=... node e2e/live.mjs
//
// Optional: ZT_UI_URL (default http://127.0.0.1:5173), PW_CHROMIUM (browser path),
// ZT_SHOTS (screenshot dir, default ../docs/screenshots).
//
// Every assertion is made against what the live backend returned; nothing is mocked.
//
// The backend runs with its default policy require_mfa_for_login=true (ADR-0010):
// every account enrols TOTP right after registering (inside the self-enrolment
// window), and then signs in again with a code, because activating a factor never
// upgrades the password-only session it was started from. The bootstrap admin must
// not have MFA yet (a fresh deployment).

import { chromium } from "playwright";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const BASE = process.env.ZT_UI_URL ?? "http://127.0.0.1:5173";
const SHOTS = path.resolve(process.env.ZT_SHOTS ?? new URL("../../docs/screenshots", import.meta.url).pathname);
const ADMIN_USER = process.env.ZT_ADMIN_USER;
const ADMIN_PASSWORD = process.env.ZT_ADMIN_PASSWORD;
if (!ADMIN_USER || !ADMIN_PASSWORD) throw new Error("set ZT_ADMIN_USER / ZT_ADMIN_PASSWORD");
fs.mkdirSync(SHOTS, { recursive: true });

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- RFC 6238 TOTP (SHA-1, 6 digits, 30 s), with the server's replay rule in mind ----
function b32decode(s) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", b32decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const v = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(v % 1e6).padStart(6, "0");
}
const lastCounter = new Map();
async function totp(secret) {
  // The server accepts ±1 step but never a counter <= the last one used.
  for (;;) {
    const now = Math.floor(Date.now() / 1000 / 30);
    const c = Math.max(now - 1, (lastCounter.get(secret) ?? -1) + 1);
    if (c <= now + 1) {
      lastCounter.set(secret, c);
      return hotp(secret, c);
    }
    await sleep(2000);
  }
}

const rnd = crypto.randomBytes(3).toString("hex");
const alice = { username: `alice_${rnd}`, password: `Sturdy-${crypto.randomBytes(9).toString("base64url")}` };
const bob = { username: `bob_${rnd}`, password: `Sturdy-${crypto.randomBytes(9).toString("base64url")}` };
const carol = { username: `carol_${rnd}`, password: `Sturdy-${crypto.randomBytes(9).toString("base64url")}` };

const browser = await chromium.launch({
  executablePath: process.env.PW_CHROMIUM || undefined,
  headless: true,
});

async function newPage(theme = "light") {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, colorScheme: theme });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: BASE });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => check("no uncaught page error", false, e.message));
  page.on("console", (m) => m.type() === "error" && !/Failed to load resource/.test(m.text()) && console.log("  console.error:", m.text()));
  return { ctx, page };
}
const shot = async (page, name, full = true) => {
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: full });
  console.log(`  screenshot ${name}.png`);
};
const nav = async (page, label) => {
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: label, exact: true }).click();
  await page.locator(".page h1").first().waitFor();
  await page.waitForTimeout(700);
};

async function register(page, u) {
  await page.getByRole("tab", { name: "Create account" }).click();
  await page.getByLabel("Username").fill(u.username);
  await page.getByLabel("Password", { exact: true }).fill(u.password);
  await page.getByLabel("Repeat password").fill(u.password);
  await page.getByRole("button", { name: "Create account" }).click();
  // F3: the server answers 202 whether or not the name was free; the UI says so.
  await page.getByText("If the username is available your account was created").waitFor();
}
async function login(page, u, secret) {
  await page.getByLabel("Username").fill(u.username);
  await page.getByLabel("Password", { exact: true }).fill(u.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (secret) {
    await page.getByLabel("Authenticator code").waitFor();
    await page.getByLabel("Authenticator code").fill(await totp(secret));
    await page.getByRole("button", { name: "Sign in" }).click();
  }
  await page.getByRole("navigation", { name: "Main" }).waitFor();
}
async function enrolMfa(page) {
  await nav(page, "Account");
  await page.getByRole("button", { name: "Start enrolment" }).click();
  await page.getByAltText("QR code for your authenticator app").waitFor();
  const secret = (await page.locator("code.secret").innerText()).replace(/\s+/g, "");
  return secret;
}
async function activateMfa(page, secret) {
  await page.getByLabel("Authenticator code").fill(await totp(secret));
  await page.getByRole("button", { name: "Activate MFA" }).click();
  await page.getByText("this session is still password-only").waitFor();
}
async function signInAgain(page, u, secret) {
  await page.getByRole("button", { name: "Sign out and sign in again" }).click();
  await page.getByRole("tab", { name: "Sign in" }).waitFor();
  await login(page, u, secret);
}
async function isRestricted(page) {
  return page.getByText("This session is restricted").isVisible();
}


async function chainVerdict(page, label) {
  const ok = await page.getByText("chain intact").isVisible();
  const types = await page.locator(".verdict table tbody tr td:first-child").allInnerTexts();
  const counts = {};
  for (const t of types) counts[t] = (counts[t] ?? 0) + 1;
  const nonAnchor = types.filter((t) => !t.startsWith("anchor-"));
  check(`${label}: no chain/signature/checkpoint findings`, nonAnchor.length === 0, JSON.stringify(counts));
  check(`${label}: verification ok (incl. provider anchors)`, ok, (await page.locator(".verdict-head").innerText()).replace(/\s+/g, " "));
}

try {
  // ------------------------------------------------------------- alice
  const A = await newPage();
  await A.page.goto(BASE);
  await A.page.getByRole("tab", { name: "Sign in" }).waitFor();
  await shot(A.page, "01-login");
  await register(A.page, alice);
  check("register: uniform 202 copy shown (no username enumeration)", true);
  await shot(A.page, "02b-register-accepted");
  await A.page.getByRole("tab", { name: "Create account" }).click();
  await A.page.getByLabel("Username").fill(`weak_${rnd}`);
  await A.page.getByLabel("Password", { exact: true }).fill("password");
  await A.page.getByLabel("Repeat password").fill("password");
  await A.page.getByRole("button", { name: "Create account" }).click();
  await A.page.getByText("422 validation-failed").waitFor();
  check("register: weak password rejected with server reasons", await A.page.getByText("password-too-short").or(A.page.getByText("password-too-common")).first().isVisible());
  await shot(A.page, "02-register-policy-error");
  await A.page.getByRole("tab", { name: "Sign in" }).click();
  await login(A.page, alice);
  check("alice signed in (password only)", await A.page.getByText(alice.username).first().isVisible());
  await A.page.waitForTimeout(700);
  check("password-only session is restricted (require_mfa_for_login)", await isRestricted(A.page));
  await shot(A.page, "03a-restricted-session");
  const aliceSecret = await enrolMfa(A.page);
  check("restricted session: Account says session management needs an MFA-verified session (M5)",
        await A.page.getByText("Listing and revoking sessions needs a session verified with your authenticator").isVisible());
  await shot(A.page, "08-account-mfa-enrol");
  await activateMfa(A.page, aliceSecret);
  check("activation tells the user to sign in again (session not upgraded)", true);
  await shot(A.page, "08b-mfa-activated-sign-in-again");
  await signInAgain(A.page, alice, aliceSecret);
  await nav(A.page, "Dashboard");
  await A.page.getByText("Files committed").waitFor();
  check("after a TOTP login the session is no longer restricted", !(await isRestricted(A.page)));
  await shot(A.page, "03-dashboard-empty-user");

  // Upload a 2.5 MiB file (3 chunks) via the file input.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zt-e2e-"));
  const payload = crypto.randomBytes(2.5 * 1024 * 1024);
  const sha = crypto.createHash("sha256").update(payload).digest("hex");
  const fname = `quarterly-report-${rnd}.bin`;
  fs.writeFileSync(path.join(tmp, fname), payload);
  await nav(A.page, "Files");
  await A.page.locator("#file-input").setInputFiles(path.join(tmp, fname));
  await A.page.getByLabel("Classification").selectOption("internal");
  await A.page.getByRole("button", { name: "Upload", exact: true }).click();
  await A.page.getByText(/Stored .* as 3 encrypted chunks/).waitFor({ timeout: 60000 });
  check("upload committed as 3 chunks", true);
  const row = A.page.getByRole("row", { name: new RegExp(fname) });
  await row.waitFor();
  check("uploaded file listed", (await row.innerText()).includes("committed"));
  const fileId = new URL(A.page.url()).searchParams.get("file");
  check("file panel opened with id", /^[0-9a-f]{32}$/.test(fileId ?? ""), fileId ?? "");

  const dl = A.page.waitForEvent("download");
  await A.page.getByRole("button", { name: "Download", exact: true }).click();
  const download = await dl;
  const saved = path.join(tmp, "dl.bin");
  await download.saveAs(saved);
  const dlSha = crypto.createHash("sha256").update(fs.readFileSync(saved)).digest("hex");
  check("download bytes sha256 == uploaded sha256", dlSha === sha, dlSha.slice(0, 16));
  check("download filename from Content-Disposition", download.suggestedFilename() === fname, download.suggestedFilename());
  await A.page.getByText("Download integrity").waitFor();
  const panelText = await A.page.locator(".subpanel").first().innerText();
  check("UI shows server X-Content-SHA256 equal to real sha", panelText.includes(sha));
  check("UI reports match", await A.page.locator(".subpanel .pill-ok", { hasText: "match" }).isVisible());
  await A.page.getByPlaceholder("64 hex characters").fill(sha);
  check("manual compare matches", await A.page.getByText("matches the downloaded content").isVisible());
  await A.page.getByRole("button", { name: "Verify replicas" }).click();
  await A.page.getByText("Replica check").waitFor();
  check("scrub reports healthy", await A.page.locator(".subpanel h3 .pill-ok", { hasText: "healthy" }).isVisible());
  await shot(A.page, "04-files-download-verified");

  // Distribution grid for this file.
  await A.page.getByRole("link", { name: "Chunk map" }).click();
  await A.page.locator("table.chunkgrid tbody tr").first().waitFor();
  const gridRows = await A.page.locator("table.chunkgrid tbody tr").count();
  const stored = await A.page.locator("table.chunkgrid td.g-stored").count();
  check("distribution grid: 3 chunk rows", gridRows === 3, String(gridRows));
  check("distribution grid: 6 stored replicas (RF 2)", stored === 6, String(stored));
  await shot(A.page, "06-distribution-user");

  // ------------------------------------------------------------- bob
  const B = await newPage();
  await B.page.goto(BASE);
  await register(B.page, bob);
  await B.page.getByRole("tab", { name: "Sign in" }).click();
  await login(B.page, bob);
  await nav(B.page, "Files");
  await B.page.getByText("403 access-denied").first().waitFor();
  check("restricted session: Files answers 403 mfa-enrollment-required with request id",
        (await B.page.getByText("mfa-enrollment-required").first().isVisible()) && (await B.page.locator(".reqid code").count()) > 0);
  await shot(B.page, "05-restricted-session-denied");
  const bobSecret = await enrolMfa(B.page);
  await activateMfa(B.page, bobSecret);
  await signInAgain(B.page, bob, bobSecret);
  await nav(B.page, "Files");
  await B.page.getByText("No files yet").waitFor();
  check("bob's file list does not contain alice's file", !(await B.page.getByText(fname).isVisible()));
  // Direct access to alice's file id: the server answers 404 (indistinguishable from unknown).
  await nav(B.page, "Storage distribution");
  const r404 = await B.page.evaluate(async (id) => {
    // Use the app's own fetch path through the proxy without a token: must be 401.
    const res = await fetch(`/api/files/${id}`);
    return res.status;
  }, fileId);
  check("unauthenticated GET /api/files/{id} is 401", r404 === 401, String(r404));
  await B.page.goto(`${BASE}/distribution?file=${fileId}`);
  await B.page.getByText("404 not-found").waitFor();
  check("bob opening alice's file id gets 404 from server", true);
  await shot(B.page, "07-user2-cannot-see-file");

  // ------------------------------------------------------------- alice shares (MFA-verified login, fresh)
  await nav(A.page, "Files");
  await A.page.getByRole("row", { name: new RegExp(fname) }).click();
  await A.page.getByLabel("Username to share with").fill(bob.username);
  await A.page.getByRole("button", { name: "Share", exact: true }).click();
  await A.page.locator(".plain-list").getByText(bob.username).waitFor();
  check("share succeeds (MFA-verified session from the TOTP login)", true);
  await nav(B.page, "Files");
  await B.page.getByText(fname).waitFor();
  check("bob now sees the shared file", true);

  // Bob downloads the shared file and gets the same hash.
  await B.page.getByRole("row", { name: new RegExp(fname) }).click();
  const dlB = B.page.waitForEvent("download");
  await B.page.getByRole("button", { name: "Download", exact: true }).click();
  const savedB = path.join(tmp, "dlb.bin");
  await (await dlB).saveAs(savedB);
  check("grantee download sha256 matches", crypto.createHash("sha256").update(fs.readFileSync(savedB)).digest("hex") === sha);

  // Audit explorer for a normal user (own scope).
  await nav(A.page, "Audit explorer");
  await A.page.getByText("(your own)").waitFor();
  check("user audit scope is own", true);
  await shot(A.page, "09-audit-user-own");

  // ------------------------------------------------------------- admin
  const C = await newPage();
  await C.page.goto(BASE);
  const adminU = { username: ADMIN_USER, password: ADMIN_PASSWORD };
  await login(C.page, adminU);
  check("admin password-only session is restricted", await (async () => { await C.page.waitForTimeout(700); return isRestricted(C.page); })());
  const adminSecret = await enrolMfa(C.page);           // bootstrap admin: may self-enrol at first login
  await activateMfa(C.page, adminSecret);
  await signInAgain(C.page, adminU, adminSecret);
  await nav(C.page, "Account");
  await shot(C.page, "10-account-admin");

  await nav(C.page, "Dashboard");
  await C.page.getByText("Files committed").waitFor();
  await C.page.waitForTimeout(500);
  await shot(C.page, "11-dashboard-admin");

  await nav(C.page, "Audit explorer");
  await C.page.getByRole("button", { name: "Verify chain" }).click();
  await C.page.locator(".verdict").waitFor();
  await chainVerdict(C.page, "audit verify (first)");
  await C.page.getByRole("button", { name: "Create checkpoint" }).click();
  await C.page.locator(".panel", { hasText: "Signed checkpoints" }).locator("tbody tr").first().waitFor();
  check("checkpoint created and listed", true);
  await C.page.getByLabel("Event type").fill("file.*");
  await C.page.getByRole("button", { name: "Search", exact: true }).click();
  await C.page.waitForTimeout(900);
  await C.page.locator("table.clickable tbody tr").first().click();
  await C.page.locator(".drawer").getByText("prev_hash").waitFor();
  check("event drawer shows seq, hash, prev_hash, details", (await C.page.locator(".drawer").innerText()).includes("Details"));
  await shot(C.page, "12-audit-admin-verify-drawer", false);
  await C.page.getByRole("button", { name: "Close details" }).click();

  await nav(C.page, "Storage distribution");
  await C.page.getByText("Provider health").waitFor();
  const faultPanel = C.page.locator(".panel.sim");
  if (await faultPanel.count()) {
    await faultPanel.getByRole("button", { name: "Show fault controls" }).click();
    // Fresh MFA from the TOTP login: no dialog expected; the dialog path is exercised below.
    await faultPanel.getByRole("button", { name: "Apply simulated fault" }).waitFor();
    await faultPanel.getByLabel("Provider").selectOption("gcs");
    await faultPanel.getByLabel("Mode").selectOption("unavailable");
    await faultPanel.getByRole("button", { name: "Apply simulated fault" }).click();
    await faultPanel.getByText("SIMULATED unavailable").waitFor();
    await C.page.locator(".hcard.injected").first().waitFor({ timeout: 15000 });
    check("simulated fault visible on provider card", (await C.page.locator(".hcard.injected").innerText()).includes("SIMULATED FAULT"));
    await shot(C.page, "13-distribution-admin-simulated-fault");
    await faultPanel.getByRole("button", { name: "Clear" }).click();
    await faultPanel.getByText("SIMULATED unavailable").waitFor({ state: "detached" });
    check("simulated fault cleared", true);
  } else {
    check("fault injection panel present (ZT_ENABLE_FAULT_INJECTION)", false);
  }

  // Step-up dialog: shorten the step-up window to 30 s (policy:write, MFA fresh), wait it out,
  // then alice deletes her file -> 403 mfa-stale -> dialog -> code -> retried -> deleted.
  await nav(C.page, "Security centre");
  await C.page.getByRole("tab", { name: "Policy" }).click();
  await C.page.getByLabel(/Step-up MFA valid for/).fill("30");
  await C.page.getByRole("button", { name: /Save 1 change/ }).click();
  await C.page.getByText("Saved. The change is audited").waitFor();
  check("admin changed policy setting (step-up 30 s)", true);
  await shot(C.page, "14-security-policy");
  check("security centre shows the separate critical-alerts list (M2)",
        await C.page.getByRole("heading", { name: "Critical alerts" }).isVisible());
  for (const [tab, name] of [["Authentication", "15-security-auth"], ["Access denied", "16-security-denied"], ["Suspicious activity", "17-security-suspicious"], ["Integrity failures", "18-security-integrity"]]) {
    await C.page.getByRole("tab", { name: tab }).click();
    await C.page.waitForTimeout(900);
    await C.page.waitForTimeout(300);
    await shot(C.page, name);
  }
  check("access-denied tab lists the restricted-session denial", await (async () => {
    await C.page.getByRole("tab", { name: "Access denied" }).click();
    await C.page.waitForTimeout(900);
    return (await C.page.locator("table tbody").first().innerText()).includes("mfa-enrollment-required");
  })());

  await nav(C.page, "Administration");
  await C.page.getByText(alice.username).waitFor();
  check("admin sees users incl. alice and bob", await C.page.getByText(bob.username).isVisible());
  await C.page.getByRole("row", { name: new RegExp(bob.username) }).getByRole("button", { name: "Manage" }).click();
  check("admin row offers MFA enrolment code and MFA reset",
        (await C.page.getByRole("button", { name: "Issue MFA enrolment code" }).isVisible()) && (await C.page.getByRole("button", { name: "Reset MFA" }).isVisible()));
  await shot(C.page, "19-admin");
  check("admin user list has no pseudonym column (M1)",
        (await C.page.locator("table thead th", { hasText: "Pseudonym" }).count()) === 0);

  // Auditor view (M1): bob becomes auditor; auditors work with pseudonyms, so the UI shows key metadata
  // only and never requests the user directory (the server answers 403 to user:list for auditors anyway).
  await C.page.locator(".editor-row").getByLabel("Role").selectOption("auditor");
  const rdlg = C.page.getByRole("dialog", { name: "Confirm with your authenticator" });
  if (await rdlg.waitFor({ timeout: 4000 }).then(() => true, () => false)) {
    await rdlg.getByLabel("Authenticator code").fill(await totp(adminSecret));
    await rdlg.getByRole("button", { name: "Verify and continue" }).click();
  }
  await C.page.getByText("Role updated.").waitFor();
  check("admin promoted bob to auditor", true);
  await C.page.getByRole("row", { name: new RegExp(bob.username) }).getByRole("button", { name: "Close" }).click();
  const directoryRequests = [];
  B.page.on("request", (req) => { if (req.url().includes("/api/admin/users")) directoryRequests.push(req.url()); });
  await B.page.reload();
  await B.page.getByRole("navigation", { name: "Main" }).waitFor();
  await nav(B.page, "Keys");
  await B.page.getByRole("heading", { name: "KMS keys (metadata only)" }).waitFor();
  check("auditor 'Keys' view: no user directory, /api/admin/users never requested (M1)",
        (await B.page.getByRole("heading", { name: /^Users/ }).count()) === 0 && directoryRequests.length === 0,
        `requests=${directoryRequests.length}`);
  await shot(B.page, "26-auditor-keys");

  // ------------------------------------------------------------- carol: recovery path (ADR-0010)
  // carol enrols inside the window; the admin then resets her factor (lost device). The window is
  // now closed for her account, so the UI must ask for an admin-issued enrolment code.
  const E = await newPage();
  await E.page.goto(BASE);
  await register(E.page, carol);
  await E.page.getByRole("tab", { name: "Sign in" }).click();
  await login(E.page, carol);
  const carolSecret1 = await enrolMfa(E.page);
  await activateMfa(E.page, carolSecret1);
  await nav(C.page, "Dashboard");
  await nav(C.page, "Administration");
  await C.page.getByRole("row", { name: new RegExp(carol.username) }).getByRole("button", { name: "Manage" }).click();
  C.page.once("dialog", (d) => d.accept());
  await C.page.getByRole("button", { name: "Reset MFA" }).click();
  await C.page.getByText(/MFA reset; \d+ session\(s\) revoked/).waitFor();
  check("admin reset carol's MFA (sessions revoked)", true);
  await E.page.goto(BASE);
  await E.page.getByRole("tab", { name: "Sign in" }).waitFor();
  await login(E.page, carol);                                   // password-only again, restricted
  await nav(E.page, "Account");
  await E.page.getByRole("button", { name: "Start enrolment" }).click();
  await E.page.getByLabel("Admin enrolment code").waitFor();
  check("enrolment after reset asks for an admin enrolment code (403 mfa-enrollment-requires-approval)", true);
  await shot(E.page, "25-mfa-enrol-needs-admin-code");
  await C.page.getByRole("button", { name: "Issue MFA enrolment code" }).click();
  const codeEl = C.page.locator(".notice code.secret");
  await codeEl.waitFor();
  const enrolCode = (await codeEl.innerText()).trim();
  check("admin issued a single-use enrolment code (shown once, not screenshotted)", /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/.test(enrolCode));
  await C.page.getByRole("button", { name: "Hide" }).click();
  await E.page.getByLabel("Admin enrolment code").fill(enrolCode);
  await E.page.getByRole("button", { name: "Start enrolment with code" }).click();
  await E.page.getByAltText("QR code for your authenticator app").waitFor();
  const carolSecret = (await E.page.locator("code.secret").innerText()).replace(/\s+/g, "");
  await activateMfa(E.page, carolSecret);
  await signInAgain(E.page, carol, carolSecret);
  check("carol enrolled with the admin code and signed in with TOTP", !(await isRestricted(E.page)));
  await E.ctx.close();

  console.log("  waiting 33 s for alice's step-up window (30 s) to lapse…");
  await sleep(33000);
  await nav(A.page, "Files");
  await A.page.getByRole("row", { name: new RegExp(fname) }).click();
  A.page.once("dialog", (d) => d.accept());
  await A.page.getByRole("button", { name: "Delete", exact: true }).click();
  const dlg = A.page.getByRole("dialog", { name: "Confirm with your authenticator" });
  await dlg.waitFor();
  check("step-up dialog opened on 403 mfa-stale", (await dlg.innerText()).includes("mfa"));
  await dlg.getByLabel("Authenticator code").fill(await totp(aliceSecret));
  await shot(A.page, "20-stepup-dialog", false);
  await dlg.getByRole("button", { name: "Verify and continue" }).click();
  await A.page.getByText(/Deleted .*Key destroyed/).waitFor({ timeout: 30000 });
  check("delete retried after step-up and succeeded", true);
  await shot(A.page, "21-files-deleted-after-stepup");

  // H1: a password change needs a FRESH second factor, through the same step-up dialog.
  console.log("  waiting 33 s for alice's step-up window (30 s) to lapse again…");
  await sleep(33000);
  await nav(A.page, "Account");
  const newAlicePassword = `Sturdy-${crypto.randomBytes(9).toString("base64url")}`;
  await A.page.getByLabel("Current password").fill(alice.password);
  await A.page.getByLabel("New password", { exact: true }).fill(newAlicePassword);
  await A.page.getByLabel("Repeat new password").fill(newAlicePassword);
  await A.page.getByRole("button", { name: "Change password" }).click();
  const pdlg = A.page.getByRole("dialog", { name: "Confirm with your authenticator" });
  await pdlg.waitFor();
  check("password change opened the step-up dialog (403 mfa-stale + step-up-mfa)", true);
  await pdlg.getByLabel("Authenticator code").fill(await totp(aliceSecret));
  await shot(A.page, "27-password-change-stepup", false);
  await pdlg.getByRole("button", { name: "Verify and continue" }).click();
  await A.page.getByText(/Password changed\. \d+ other session\(s\) signed out\./).waitFor({ timeout: 30000 });
  check("password change retried after step-up and succeeded", true);
  alice.password = newAlicePassword;

  // Restore default step-up window (admin MFA may be stale by now -> dialog for admin too).
  await nav(C.page, "Security centre");
  await C.page.getByRole("tab", { name: "Policy" }).click();
  await C.page.getByLabel(/Step-up MFA valid for/).fill("600");
  await C.page.getByRole("button", { name: /Save 1 change/ }).click();
  const adlg = C.page.getByRole("dialog", { name: "Confirm with your authenticator" });
  if (await adlg.waitFor({ timeout: 5000 }).then(() => true, () => false)) {
    check("admin step-up dialog opened for policy:write (MFA stale)", true);
    await adlg.getByLabel("Authenticator code").fill(await totp(adminSecret));
    await adlg.getByRole("button", { name: "Verify and continue" }).click();
  }
  await C.page.getByText("Saved. The change is audited").waitFor();
  check("policy restored to 600 s", true);

  // Verify chain again after all of the above.
  await nav(C.page, "Audit explorer");
  await C.page.getByRole("button", { name: "Verify chain" }).click();
  await C.page.locator(".verdict").waitFor();
  await chainVerdict(C.page, "audit verify (final)");
  await shot(C.page, "22-audit-admin-final");

  // Dark theme render of the dashboard.
  const D = await newPage("dark");
  await D.page.goto(BASE);
  await login(D.page, alice, aliceSecret);
  await D.page.getByText("Files committed").waitFor();
  await D.page.waitForTimeout(400);
  await shot(D.page, "23-dashboard-dark");
  await nav(D.page, "Storage distribution");
  await D.page.waitForTimeout(400);
  await shot(D.page, "24-distribution-dark");

  // Logout calls the API; the refresh cookie is then useless.
  await D.page.getByRole("button", { name: "Sign out" }).click();
  await D.page.getByRole("tab", { name: "Sign in" }).waitFor();
  const afterLogout = await D.page.evaluate(async () => (await fetch("/api/auth/refresh", { method: "POST" })).status);
  check("refresh after logout is 401", afterLogout === 401, String(afterLogout));
  fs.rmSync(tmp, { recursive: true, force: true });
} catch (e) {
  check("walk-through completed", false, String(e && e.message ? e.message.split("\n")[0] : e));
  console.error(e);
} finally {
  await browser.close();
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exitCode = failed.length ? 1 : 0;
}
