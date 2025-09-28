import * as openid from "openid-client";

console.log("Loaded openid-client keys:", Object.keys(openid));
console.log("openid-client package version:", (await import("openid-client/package.json")).version);

const { Issuer, generators } = openid;
console.log("Issuer typeof:", typeof Issuer);
console.log("Generators keys:", Object.keys(generators || {}));

const { OIDC_ISSUER } = process.env;
console.log("OIDC_ISSUER env:", OIDC_ISSUER);

if (!OIDC_ISSUER) {
    console.error("Missing OIDC_ISSUER env var!");
    process.exit(1);
}

try {
    console.log("Calling Issuer.discover...");
    const issuer = await Issuer.discover(OIDC_ISSUER);
    console.log("Discovery result issuer.metadata:", issuer.metadata);
} catch (err) {
    console.error("Error from Issuer.discover:", err);
}
