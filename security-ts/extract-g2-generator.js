const { Hiver } = require('./dist/index.js');

async function main() {
    // Initialize BLS
    await Hiver.init();

    // Generate keypair for secret key = 1
    const secretKey = Hiver.toSecretKey("01"); // hex "01" = 1
    const publicKey = Hiver.generatePublicKey(secretKey);

    // Serialize to hex
    const publicKeyHex = Hiver.toHex(publicKey);
    const publicKeyBytes = Hiver.toBuffer(publicKey);

    console.log("G2 Generator (hex):", publicKeyHex);
    console.log("G2 Generator (bytes):", Array.from(publicKeyBytes));
    console.log("G2 Generator length:", publicKeyBytes.length);
}

main().catch(console.error);
