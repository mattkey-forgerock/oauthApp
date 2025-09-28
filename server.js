import express from "express";
import session from "express-session";
const pkg = require("openid-client/package.json");
console.log("openid-client version actually loaded:", pkg.version);
import { Issuer, generators } from "openid-client";
console.log("Issuer type is:", typeof Issuer);

const {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    SESSION_SECRET,
    RENDER_EXTERNAL_URL,
    PORT = 10000,
} = process.env;

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !RENDER_EXTERNAL_URL) {
    throw new Error("Missing env vars: OIDC_ISSUER, OIDC_CLIENT_ID, RENDER_EXTERNAL_URL");
}

const OIDC_REDIRECT_URI = `${RENDER_EXTERNAL_URL}/callback`;

console.log("Startup environment:");
console.log("OIDC_ISSUER:", OIDC_ISSUER);
console.log("OIDC_CLIENT_ID:", OIDC_CLIENT_ID);
console.log("RENDER_EXTERNAL_URL:", RENDER_EXTERNAL_URL);
console.log("PORT:", PORT);

const app = express();
app.set("trust proxy", 1);

app.use(
    session({
        name: "sid",
        secret: SESSION_SECRET || "change-me",
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: true, sameSite: "lax" },
    })
);

let cachedClient;
async function getClient() {
    if (cachedClient) return cachedClient;
    const issuer = await Issuer.discover(OIDC_ISSUER);
    cachedClient = new issuer.Client({
        client_id: OIDC_CLIENT_ID,
        token_endpoint_auth_method: "none",
        redirect_uris: [OIDC_REDIRECT_URI],
        response_types: ["code"],
    });
    return cachedClient;
}

function ensureAuth(req, res, next) {
    if (req.session?.id_token) return next();
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
        res.redirect(authUrl);
    } catch (e) {
        next(e);
    }
});

app.get("/callback", async (req, res, next) => {
    try {
        const client = await getClient();
        const params = client.callbackParams(req);

        const tokenSet = await client.callback(OIDC_REDIRECT_URI, params, {
            state: req.session.state,
            nonce: req.session.nonce,
            code_verifier: req.session.code_verifier,
        });

        req.session.id_token = tokenSet.id_token;
        req.session.access_token = tokenSet.access_token;
        req.session.userinfo = tokenSet.claims();

        delete req.session.code_verifier;
        delete req.session.state;
        delete req.session.nonce;

        res.redirect("/");
    } catch (e) {
        next(e);
    }
});

app.get("/logout", async (req, res) => {
    const idToken = req.session.id_token;
    req.session.destroy(() => { });
    try {
        const client = await getClient();
        const endSession = client.issuer.metadata.end_session_endpoint;
        if (endSession && idToken) {
            const url = new URL(endSession);
            url.searchParams.set("id_token_hint", idToken);
            url.searchParams.set("post_logout_redirect_uri", RENDER_EXTERNAL_URL);
            return res.redirect(url.toString());
        }
    } catch (_) { }
    res.redirect("/");
});

app.get("/", ensureAuth, (req, res) => {
    res.type("text").send("hello world");
});

app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(500).send("Something went wrong.");
});

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`);
});
