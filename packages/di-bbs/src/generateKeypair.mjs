import { generateBls12381G2KeyPair } from "@mattrglobal/bbs-signatures";

const kp = await generateBls12381G2KeyPair();
console.log(
  JSON.stringify(
    {
      ISSUER_BBS_PUBLIC_KEY_B64U: Buffer.from(kp.publicKey).toString("base64url"),
      ISSUER_BBS_SECRET_KEY_B64U: Buffer.from(kp.secretKey).toString("base64url")
    },
    null,
    2
  )
);
