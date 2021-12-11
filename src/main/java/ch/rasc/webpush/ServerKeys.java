package ch.rasc.webpush;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * VAPID keys from https://vapidkeys.com/
 *
 * @apiNote https://developers.google.com/web/fundamentals/push-notifications/web-push-protocol#application_server_keys
 */
public class ServerKeys {

  private final String publicKeyBase64;
  private final ECPublicKey publicKey;
  private final ECPrivateKey privateKey;

  public ServerKeys(String vapidPublicKey, String vapidPrivateKey) throws InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    final CryptoService cryptoService = new CryptoService();
    this.publicKeyBase64 = vapidPublicKey;
    this.publicKey = cryptoService.fromUncompressedECPublicKey(vapidPublicKey);
    this.privateKey = cryptoService.fromUncompressedECPrivateKey(vapidPrivateKey, publicKey);
  }

  public String getPublicKeyBase64() {
    return this.publicKeyBase64;
  }

  public ECPrivateKey getPrivateKey() {
    return this.privateKey;
  }

  public ECPublicKey getPublicKey() {
    return this.publicKey;
  }

}
