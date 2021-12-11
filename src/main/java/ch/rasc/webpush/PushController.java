package ch.rasc.webpush;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import ch.rasc.webpush.dto.Subscription;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * Web push and signed JWTs
 * @apiNote https://developers.google.com/web/fundamentals/push-notifications/web-push-protocol#web_push_and_signed_jwts
 */
public class PushController {

  private final ServerKeys serverKeys;

  private final Algorithm jwtAlgorithm;

  public PushController(ServerKeys serverKeys) {
    this.serverKeys = serverKeys;
    this.jwtAlgorithm = Algorithm.ECDSA256(this.serverKeys.getPublicKey(), this.serverKeys.getPrivateKey());
  }

  public String getToken(String origin) {
    Date expires = new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(12));
    return JWT.create()
            .withAudience(origin)
            .withExpiresAt(expires)
            .withSubject("mailto:example@example.com")
            .sign(this.jwtAlgorithm);
  }

  public String getAuthorization(URI endpointURI) {
    String origin = endpointURI.getScheme() + "://" + endpointURI.getHost();
    final String token = getToken(origin);
    return "vapid t=" + token + ", k=" + this.serverKeys.getPublicKeyBase64();
  }

  public HttpRequest.Builder prepareRequest(Subscription subscription, byte[] encryptedPayload) {
    URI endpointURI = URI.create(subscription.getEndpoint());
    return HttpRequest.newBuilder(endpointURI)
            .POST(HttpRequest.BodyPublishers.ofByteArray(encryptedPayload))
            .header("Content-Type", "application/octet-stream")
            .header("Content-Encoding", "aes128gcm")
            .header("TTL", "180")
            .header("Authorization", getAuthorization(endpointURI));
  }

}
