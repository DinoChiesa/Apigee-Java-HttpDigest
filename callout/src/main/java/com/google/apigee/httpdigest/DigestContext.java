package com.google.apigee.httpdigest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.RandomString;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DigestContext {
  public Map<String, String> challengeParams;
  public String username;
  public String password;
  public int nonceCount;
  public String method;
  public String uri;
  public String cnonce;
  private String algorithm;
  public static final Logger LOGGER = LoggerFactory.getLogger(DigestContext.class);

  public DigestContext(String wwwAuthenticateHeader) {
    nonceCount = 0;
    LOGGER.debug("header({})", wwwAuthenticateHeader);

    if (wwwAuthenticateHeader.startsWith("WWW-Authenticate: Digest ")) {
      LOGGER.debug("header startsWith \"WWW-Authenticate: Digest\"");
      wwwAuthenticateHeader =
        wwwAuthenticateHeader.substring("WWW-Authenticate: Digest ".length());
    } else if (wwwAuthenticateHeader.startsWith("Digest ")) {
      LOGGER.debug("header startsWith \"Digest\"");
      wwwAuthenticateHeader = wwwAuthenticateHeader.substring("Digest ".length());
    } else {
      throw new IllegalStateException("Malformed WWW-Authenticate header");
    }

    String[] parts = wwwAuthenticateHeader.split(", *");
    if (parts.length < 2) {
      throw new IllegalStateException("Malformed WWW-Authenticate header");
    }

    challengeParams =
      Arrays.stream(parts)
      .map(s -> s.split("="))
      .map(
           A ->
           new AbstractMap.SimpleEntry<String, String>(
                                                       A[0],
                                                       (A[1].startsWith("\"")) ? A[1].substring(1, A[1].length() - 1) : A[1]))
      .collect(
               Collectors.toMap
               ( Map.Entry::getKey, Map.Entry::getValue, (old, cur) -> cur, LinkedHashMap::new));

    algorithm = challengeParams.get("algorithm");
    if (algorithm== null) {
      algorithm = "MD5"; // default
    }
    else if (!algorithm.equals("MD5") && !algorithm.equals("SHA-256") ) {
        throw new IllegalStateException("Unsupported digest algorithm");
    }

    LOGGER.debug("challengeParams({})", challengeParams);
  }

  public DigestContext withUsername(String username) {
    this.username = username;
    return this;
  }

  public DigestContext withPassword(String password) {
    this.password = password;
    return this;
  }

  public DigestContext withMethod(String method) {
    this.method = method;
    return this;
  }

  public DigestContext withUri(String uri) {
    this.uri = uri;
    return this;
  }

  /* exposed for testing only */
  public DigestContext withCnonce(String cnonce) {
    this.cnonce = cnonce;
    LOGGER.debug("cnonce <= ({})", cnonce);
    return this;
  }

  String q(String s) {
    return "\"" + s + "\"";
  }

  String getA1() throws IllegalStateException {
    String realm = challengeParams.get("realm");
      if (realm == null) {
        throw new IllegalStateException("missing realm");
      }
      return String.format("%s:%s:%s", username, realm, password);
  }

  String getA2() throws IllegalStateException {
    String qop = challengeParams.get("qop");

    if ("auth".equals(qop)) {
      return String.format("%s:%s", method, uri);
    } else if ("auth-int".equals(qop)) {
      throw new IllegalStateException("qop=auth-int is Not yet implemented");
    }
    throw new IllegalStateException("unsupported qop");
  }

  String KD(String secret, String data)
    throws NoSuchAlgorithmException, UnsupportedEncodingException {
    return H(secret + ":" + data);
  }

  String H(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    return digestHex(message);
  }

  String digestHex(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    byte[] hashBytes = md.digest(message.getBytes("UTF-8"));
    String hashHex = Base16.encode(hashBytes);
    return hashHex;
  }

  String getRequestDigest() throws NoSuchAlgorithmException, UnsupportedEncodingException {
    String qop = challengeParams.get("qop");
    LOGGER.debug("qop({})", qop);
    nonceCount++;
    if (cnonce == null) {
      cnonce = RandomString.randomString();
      LOGGER.debug("cnonce <= ({})", cnonce);
    }

    if ("auth-int".equals(qop) || "auth".equals(qop)) {
      // request-digest  = <"> < KD ( H(A1),     unq(nonce-value)
      //                                     ":" nc-value
      //                                     ":" unq(cnonce-value)
      //                                     ":" unq(qop-value)
      //                                     ":" H(A2)
      //                             ) <">
      String A1 = getA1();
      String A2 = getA2();
      String param2 =
        String.format("%s:%s:%s:%s:%s",
                      challengeParams.get("nonce"),
                      String.format("%08d", nonceCount),
                      cnonce,
                      challengeParams.get("qop"),
                      H(A2));
      return KD(H(A1), param2);
    } else if (qop == null) {
      // request-digest  =
      //     <"> < KD ( H(A1), unq(nonce-value) ":" H(A2) ) >   <">
      String A1 = getA1();
      String A2 = getA2();
      throw new IllegalStateException("qop=null is Not implemented");
    }
    throw new IllegalStateException("unsupported qop");
  }

  public String computeAuthzHeader()
    throws NoSuchAlgorithmException, UnsupportedEncodingException {

    // Authorization: Digest username="Mufasa",
    //                  realm="testrealm@host.com",
    //                  nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
    //                  uri="/dir/index.html",
    //                  qop=auth,
    //                  nc=00000001,
    //                  cnonce="0a4f113b",
    //                  response="6629fae49393a05397450978507c4ef1",
    //                  opaque="5ccc069c403ebaf9f0171e9517f40e41"

    // Order is not important.

    Map<String, String> responseParams = new LinkedHashMap<String, String>();
    responseParams.put("username", q(username));
    responseParams.put("realm", q(challengeParams.get("realm")));
    responseParams.put("uri", q(uri));
    responseParams.put("algorithm", challengeParams.get("algorithm"));
    responseParams.put("nonce", q(challengeParams.get("nonce")));
    responseParams.put("qop", challengeParams.get("qop"));

    String response = getRequestDigest();
    LOGGER.debug("response <= ({})", response);

    responseParams.put("nc", String.format("%08d", nonceCount));
    responseParams.put("cnonce", q(cnonce));

    responseParams.put("response", q(response));

    if (challengeParams.get("opaque") != null) {
      responseParams.put("opaque", q(challengeParams.get("opaque")));
    }

    String authzHeader = "Digest "
      + responseParams.keySet().stream()
      .map(key -> String.format("%s=%s", key, responseParams.get(key)))
      .collect(Collectors.joining(", "));
    LOGGER.debug("authzHeader <= ({})", authzHeader);
    return authzHeader;

  }
}
