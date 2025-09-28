import express from "express";
import session from "express-session";
import { discovery } from "openid-client";
import crypto from "crypto";

const {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    SESSION_SECRET,
    RENDER_EXTERNAL_URL,
    PORT = 10000,
} = process.env;

// PKCE helpers
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString("hex");
}
function generateCodeChallenge(verifier) {
    return crypto
        .createHash("sha256")
        .update(verifier)
        .digest()
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !RENDER_EXTERNAL_URL) {
    throw new Error("Missing required env vars");
}
const OIDC_REDIRECT_URI = `${RENDER_EXTERNAL_URL}/callback`;

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
    console.log("Discovering issuer:", OIDC_ISSUER);
    const { client } = await discovery({
        issuer: OIDC_ISSUER,
        client_id: OIDC_CLIENT_ID,
        token_endpoint_auth_method: "none",
        redirect_uris: [OIDC_REDIRECT_URI],
        response_types: ["code"],
    });
    console.log("Discovered client metadata:", client.metadata);
    cachedClient = client;
    return client;
}

function ensureAuth(req, res, next) {
    if (req.session?.id_token) return next();
    return res.redirect("/login");
}

app.get("/login", async (req, res, next) => {
    try {
        const client = await getClient();
        const code_verifier = generateCodeVerifier();
        const code_challenge = generateCodeChallenge(code_verifier);
        const state = crypto.randomBytes(16).toString("hex");
        const nonce = crypto.randomBytes(16).toString("hex");

        req.session.code_verifier = code_verifier;
        req.session.state = state;
        req.session.nonce = nonce;

        const authUrl = client.buildAuthorizationUrl({
            scope: "openid profile email",
            code_challenge,
            code_challenge_method: "S256",
            state,
            nonce,
        });

        console.log("Redirecting to:", authUrl);
        res.redirect(authUrl);
    } catch (err) {
        console.error("Login error:", err);
        next(err);
    }
});

app.get("/callback", async (req, res, next) => {
    try {
        console.log("Callback params:", req.query);
        const client = await getClient();

        const tokenSet = await client.authorizationCodeGrant({
            parameters: req.query,
            checks: {
                state: req.session.state,
                nonce: req.session.nonce,
                code_verifier: req.session.code_verifier,
            },
        });

        console.log("TokenSet:", tokenSet);
        console.log("Claims:", tokenSet.claims());

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

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`);
});
