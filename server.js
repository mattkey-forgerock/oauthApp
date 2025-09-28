import express from "express";
import session from "express-session";
import { Issuer, generators } from "openid-client";
import { createRequire } from "module";
import { readFileSync } from "fs";

// --- Log the real installed version ---
const require = createRequire(import.meta.url);
const pkgPath = require.resolve("openid-client/package.json");
const version = JSON.parse(readFileSync(pkgPath, "utf8")).version;
console.log("=== Runtime info ===");
console.log("openid-client version:", version);
console.log("====================");

const {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    SESSION_SECRET,
    RENDER_EXTERNAL_URL,
    PORT = 10000,
} = process.env;

console.log("Startup environment:");
console.log("OIDC_ISSUER:", OIDC_ISSUER);
console.log("OIDC_CLIENT_ID:", OIDC_CLIENT_ID);
console.log("RENDER_EXTERNAL_URL:", RENDER_EXTERNAL_URL);
console.log("SESSION_SECRET set:", !!SESSION_SECRET);
console.log("PORT:", PORT);

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !RENDER_EXTERNAL_URL) {
    throw new Error("Missing required env vars: OIDC_ISSUER, OIDC_CLIENT_ID, RENDER_EXTERNAL_URL");
}

const OIDC_REDIRECT_URI = `${RENDER_EXTERNAL_URL}/callback`;
console.log("OIDC_REDIRECT_URI:", OIDC_REDIRECT_URI);

const app = express();
app.set("trust proxy", 1);

app.use(
    session({
        name: "sid",
        secret: SESSION_SECRET || "insecure-default",
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: true, sameSite: "lax" },
    })
);

let cachedClient;
async function getClient() {
    if (cachedClient) return cachedClient;
    console.log("Calling Issuer.discover for:", OIDC_ISSUER);
    const issuer = await Issuer.discover(OIDC_ISSUER);
    console.log("Discovered issuer metadata keys:", Object.keys(issuer.metadata));
    cachedClient = new issuer.Client({
        client_id: OIDC_CLIENT_ID,
        token_endpoint_auth_method: "none",
        redirect_uris: [OIDC_REDIRECT_URI],
        response_types: ["code"],
    });
    console.log("OIDC client created with metadata:", cachedClient.metadata);
    return cachedClient;
}

function ensureAuth(req, res, next) {
    if (req.session?.id_token) {
        console.log("User authenticated with claims:", req.session.userinfo);
        return next();
    }
    console.log("User not authenticated, redirecting to /login");
    return res.redirect("/login");
}

app.get("/login", async (req, res, next) => {
    try {
        const client = await getClient();
        const code_verifier = generators.codeVerifier();
        const code_challenge = generators.codeChallenge(code_verifier);
        const state = generators.state();
        const nonce = generators.nonce();

        req.session.code_verifier = code_verifier;
        req.session.state = state;
        req.session.nonce = nonce;

        const authUrl = client.authorizationUrl({
            scope: "openid profile email",
            code_challenge,
            code_challenge_method: "S256",
            state,
            nonce,
        });

        console.log("Redirecting user to:", authUrl);
        res.redirect(authUrl);
    } catch (err) {
        console.error("Login error:", err);
        next(err);
    }
});

app.get("/callback", async (req, res, next) => {
    try {
        console.log("Callback received with query params:", req.query);
        const client = await getClient();
        const params = client.callbackParams(req);

        const tokenSet = await client.callback(OIDC_REDIRECT_URI, params, {
            state: req.session.state,
            nonce: req.session.nonce,
            code_verifier: req.session.code_verifier,
        });

        console.log("TokenSet received:", tokenSet);
        console.log("Claims extracted:", tokenSet.claims());

        req.session.id_token = tokenSet.id_token;
        req.session.access_token = tokenSet.access_token;
        req.session.userinfo = tokenSet.claims();

        res.redirect("/");
    } catch (err) {
        console.error("Callback error:", err);
        next(err);
    }
});

app.get("/", ensureAuth, (req, res) => {
    res.type("text").send("hello world");
});

app.use((err, _req, res, _next) => {
    console.error("Unhandled error:", err);
    res.status(500).send("Something went wrong.");
});

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`);
});
