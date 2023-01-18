// Copyright 2016 Apigee Corp, 2017-2023 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ------------------------------------------------------------------

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import mockit.Mock;
import mockit.MockUp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestHttpDigestCallout {
  public static final Logger LOGGER = LoggerFactory.getLogger(TestHttpDigestCallout.class);

  MessageContext msgCtxt;
  Message message;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void beforeMethod() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String, Object> variables;

          public void $init() {
            variables = new HashMap<String, Object>();
          }

          @Mock()
          public Object getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            return variables.get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }

            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }

          @Mock()
          public Message getMessage() {
            return message;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();

    message = new MockUp<Message>() {}.getMockInstance();
  }

  Map<String, String> parseDigestAuthzHeader(String authzHeader) {
    Assert.assertTrue(authzHeader.startsWith("Digest "));
    authzHeader = authzHeader.substring("Digest ".length());
    String[] parts = authzHeader.split(", *");
    Assert.assertTrue(parts.length > 3);
    return Arrays.stream(parts)
        .map(s -> s.split("="))
        .map(A -> new AbstractMap.SimpleEntry<String, String>(A[0], A[1]))
        .collect(
            Collectors.toMap(
                Map.Entry::getKey, Map.Entry::getValue, (old, cur) -> cur, HashMap::new));
  }

  @Test
  public void rfc7616_MD5_testcase() throws Exception {
    String challengeHeader =
        "WWW-Authenticate: "
            + "Digest "
            + "realm=\"http-auth@example.org\", "
            + "qop=\"auth\", "
            + "algorithm=MD5, "
            + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
            + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    String username = "Mufasa";
    String password = "Circle of Life";
    String method = "GET";
    String uri = "/dir/index.html";
    String cnonceOverride = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

    runOneTest(
        "RFC7616 MD5 example", challengeHeader, username, password, method, uri, cnonceOverride);

    final String expectedAuthzHeader =
        "Digest"
            + " username=\"Mufasa\","
            + " realm=\"http-auth@example.org\","
            + " uri=\"/dir/index.html\","
            + " algorithm=MD5,"
            + " nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
            + " nc=00000001,"
            + " cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\","
            + " qop=auth,"
            + " response=\"8ca523f5e9506fed4657c9700eebdbec\","
            + " opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";

    final Map<String, String> expectedParams = parseDigestAuthzHeader(expectedAuthzHeader);
    //final String computedAuthzHeader = msgCtxt.getVariable("message.header.authorization");
    final String computedAuthzHeader = msgCtxt.getVariable("digest_computed_authzheader");
    final Map<String, String> actualParams = parseDigestAuthzHeader(expectedAuthzHeader);

    for (Map.Entry<String, String> entry : expectedParams.entrySet()) {
      String key = entry.getKey();
      String expectedValue = entry.getValue();
      String actualValue = actualParams.get(key);
      LOGGER.debug("param({}) expected({}) actual({})", key, expectedValue, actualValue);
      Assert.assertEquals(actualValue, expectedValue, "param " + key);
    }
    System.out.println("=========================================================");
  }

  @Test
  public void rfc7616_MD5_testcase_random_cnonce() throws Exception {
    String challengeHeader =
        "WWW-Authenticate: "
            + "Digest "
            + "realm=\"http-auth@example.org\", "
            + "qop=\"auth\", "
            + "algorithm=MD5, "
            + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
            + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    String username = "Mufasa";
    String password = "Circle of Life";
    String method = "GET";
    String uri = "/dir/index.html";

    runOneTest("RFC7616 MD5 example", challengeHeader, username, password, method, uri, null);

    final String expectedAuthzHeader =
        "Digest"
            + " username=\"Mufasa\","
            + " realm=\"http-auth@example.org\","
            + " uri=\"/dir/index.html\","
            + " algorithm=MD5,"
            + " nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
            + " nc=00000001,"
            + " cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\","
            + " qop=auth,"
            + " response=\"8ca523f5e9506fed4657c9700eebdbec\","
            + " opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";

    final Map<String, String> expectedParams = parseDigestAuthzHeader(expectedAuthzHeader);
    final String computedAuthzHeader = msgCtxt.getVariable("digest_computed_authzheader");
    final Map<String, String> actualParams = parseDigestAuthzHeader(computedAuthzHeader);

    for (Map.Entry<String, String> entry : expectedParams.entrySet()) {
      String key = entry.getKey();
      String expectedValue = entry.getValue();
      String actualValue = actualParams.get(key);
      if (!key.equals("response") && !key.equals("cnonce")) {
        LOGGER.debug("param({}) expected({}) actual({})", key, expectedValue, actualValue);
        Assert.assertEquals(actualValue, expectedValue, "param " + key);
      } else {
        LOGGER.debug("param({}) NOT-expected({}) actual({})", key, expectedValue, actualValue);
        Assert.assertNotEquals(actualValue, expectedValue, "param " + key);
      }
    }
    System.out.println("=========================================================");
  }

  public void runOneTest(
      String description,
      String header,
      String username,
      String password,
      String method,
      String uri,
      String cnonceOverride)
      throws Exception {
    System.out.printf("%s\n", description);

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("challenge-header", header);
    properties.put("username", username);
    properties.put("password", password);
    properties.put("method", method);
    properties.put("uri", uri);
    properties.put("cnonce", cnonceOverride); // maybe null

    HttpDigest callout = new HttpDigest(properties);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);

    ExecutionResult expectedResult = ExecutionResult.SUCCESS;
    Assert.assertEquals(actualResult, expectedResult, "result not as expected");
  }
}
