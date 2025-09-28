import express from "express";
import session from "express-session";
import {
    discovery,
    randomPKCECodeVerifier,
    calculatePKCECodeChallenge,
    randomState,
    randomNonce
} from "openid-client";

const {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    SESSION_SECRET,
    RENDER_EXTERNAL_URL,
    PORT = 10000,
} = process.env;

// ---- Log environment ----
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
    console.log("Discovering OIDC issuer:", OIDC_ISSUER);

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
    if (req.session?.id_token) {
        console.log("User is authenticated, claims:", req.session.userinfo);
        return next();
    }
    console.log("User not authenticated, redirecting to /login");
    return res.redirect("/login");
}

app.get("/login", async (req, res, next) => {
    try {
        console.log("Starting login flow...");
        const client = await getClient();

        const code_verifier = randomPKCECodeVerifier();
        const code_challenge = calculatePKCECodeChallenge(code_verifier);
        const state = randomState();
        const nonce = randomNonce();

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

        console.log("Redirecting to authorization URL:", authUrl);
        res.redirect(authUrl);
    } catch (e) {
        console.error("Login error:", e);
        next(e);
    }
});

app.get("/callback", async (req, res, next) => {
    try {
        console.log("Received callback with params:", req.query);
        const client = await getClient();

        const tokenSet = await client.authorizationCodeGrant({
            parameters: req.query,
            checks: {
                state: req.session.state,
                nonce: req.session.nonce,
                code_verifier: req.session.code_verifier,
            },
        });

        console.log("TokenSet received:", tokenSet);
        console.log("Claims:", tokenSet.claims());

        req.session.id_token = tokenSet.id_token;
        req.session.access_token = tokenSet.access_token;
        req.session.userinfo = tokenSet.claims();

        delete req.session.code_verifier;
        delete req.session.state;
        delete req.session.nonce;

        res.redirect("/");
    } catch (e) {
        console.error("Callback error:", e);
        next(e);
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
