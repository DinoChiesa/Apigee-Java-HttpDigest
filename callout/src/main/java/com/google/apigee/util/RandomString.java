package com.google.apigee.util;

import java.security.SecureRandom;
import java.util.Random;

public class RandomString {

  static final Random random = new SecureRandom();
  static final char[] B64URL_CHARSET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ-abcdefghijklmnopqrstuvwxyz_0123456789".toCharArray();

  static final char[] CHARSET_AZ_09 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

  public static String randomString(char[] characterSet, int length) {
    char[] result = new char[length];
    for (int i = 0; i < result.length; i++) {
      // picks a random index out of character set > random character
      int randomCharIndex = random.nextInt(characterSet.length);
      result[i] = characterSet[randomCharIndex];
    }
    return new String(result);
  }

  public static String randomAlphanumericString(int length) {
    return randomString(CHARSET_AZ_09, length);
  }

  public static String randomAlphanumericString() {
    return randomAlphanumericString(32);
  }

  public static String randomString(int length) {
    return randomString(B64URL_CHARSET, length);
  }

  public static String randomString() {
    return randomString(32);
  }
}
