package net.simon04.webpush;

import net.simon04.webpush.dto.Subscription;
import net.simon04.webpush.dto.SubscriptionKeys;

import java.net.http.HttpRequest;

class PushControllerTest {

    public static void main(String[] args) throws Exception {
        final ServerKeys serverKeys = new ServerKeys(
                "BEgjVJRSctSvDIJ_7Hvo7ZjAXeSOO2fFGkiofbXh41O4FWqh6aIgVDI8Wp9fU2HRv-7qglih19Ba2GRXHUh5jTo",
                "uAICF2Y8mCGJpSfVLm6L1SOlxb59jAT819-g3Xj5uL0");
        final SubscriptionKeys subscriptionKeys = new SubscriptionKeys(
                "BEoQn2VR93GQ9gBxOo4pvdmgOyO1eiSDjUy7blwez1Vu_99PDswkEtV6m7cuwB60A8WlYq6lGKTZLet7PbnAEow",
                "wnAO8hfJGyGtdK3uUmVI8g");
        final Subscription subscription1 = new Subscription(
                "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABgHwSx9txJscXfY5Dz82G5Xs7b6U0zROFXDPDhSM9D4KCTEmGxJTLfZ7arYnRlS3BexTWFeLA8pfzDEHjd8tX9UBmLuUaR3Xnim3Q-2Xa3UddaHRbh4NT2mKFMGBDmIZ4208OgpVECiuoI8UANC9B3IOf2CpduP58fUz1VE857gyNeHsw",
                null, subscriptionKeys);
        final String payload = "{\"title\": \"Hello World!\", \"body\": \"Hello World!\"}";

        final byte[] encrypted = new CryptoService().encrypt(payload, subscriptionKeys, 0);
        HttpRequest httpPost = new PushController(serverKeys).prepareRequest(subscription1, encrypted).build();
        // HttpClient.newHttpClient().send(httpPost, HttpResponse.BodyHandlers.discarding());
        System.out.println(httpPost);
        System.out.println(httpPost.headers());
    }

}
