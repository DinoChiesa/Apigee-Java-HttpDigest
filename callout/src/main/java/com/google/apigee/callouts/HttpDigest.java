// HttpDigest.java
//
// Copyright (c) 2018-2023 Google LLC
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

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.Message;
import com.google.apigee.httpdigest.DigestContext;
import java.util.Map;

public class HttpDigest extends CalloutBase implements Execution {

  public HttpDigest(Map properties) {
    super(properties);
  }

  public String getVarnamePrefix() {
    return "digest_";
  }

  protected String getOutputMessage(MessageContext msgCtxt) throws Exception {
    String dest = getSimpleOptionalProperty("message", msgCtxt);
    // if (dest == null) {
    //     return "message";
    // }
    return dest;
  }

  protected String getAuthenticateHeader(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("challenge-header", msgCtxt);
  }

  protected String getUsername(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("username", msgCtxt);
  }

  protected String getPassword(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("password", msgCtxt);
  }

  protected String getUri(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("uri", msgCtxt);
  }

  protected String getMethod(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("method", msgCtxt);
  }

  protected String getCnonce(MessageContext msgCtxt) throws Exception {
    return getSimpleOptionalProperty("cnonce", msgCtxt);
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      DigestContext digestContext =
          new DigestContext(getAuthenticateHeader(msgCtxt))
              .withUsername(getUsername(msgCtxt))
              .withPassword(getPassword(msgCtxt))
              .withMethod(getMethod(msgCtxt))
              .withUri(getUri(msgCtxt))
              .withCnonce(getCnonce(msgCtxt));

      String authzHeader = digestContext.computeAuthzHeader();
      String messageName = getOutputMessage(msgCtxt);
      if (messageName != null) {
        Message destinationMessage = (Message) msgCtxt.getVariable(messageName);
        if (destinationMessage != null) {
          msgCtxt.setVariable(messageName + ".header.authorization", authzHeader);
        }
        else {
          msgCtxt.setVariable(varName("warning"), String.format("the message %s does not exist", messageName));
        }
      }
      msgCtxt.setVariable(varName("computed_authzheader"), authzHeader);

      return ExecutionResult.SUCCESS;
    } catch (Exception e) {
      if (getDebug()) {
        System.out.println(getStackTrace(e));
      }
      setExceptionVariables(e, msgCtxt);
      msgCtxt.setVariable(varName("stacktrace"), getStackTrace(e));
      return ExecutionResult.SUCCESS;
    }
  }
}
