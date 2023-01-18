# Apigee HTTP Digest Callout

This directory contains the Java source code and pom.xml file required to build
a Java callout for Apigee that computes an HTTP Digest Authorization header, as
defined in [IETF RFC 7616](https://datatracker.ietf.org/doc/rfc7616/). This
supports the "caller side" of HTTP Digest authentication.

There are some restrictions:
  - The only qop supported is "auth"
  - Only MD5 and SHA-256 algorithms
  - the callout always uses a nonceCount of 1

This callout does not SEND the message. For that you should use the Apigee target or ServiceCallout.
This callout computes the Authorization header that is suitable for the message.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using this policy

You do not need to build the source code in order to use the policy in Apigee.
All you need is the built JAR, and the appropriate configuration for the policy.
If you want to build it, feel free.  The instructions are at the bottom of this readme.


1. make sure  the required jar files are available in your `apiproxy/resources/java directory`.
   There are three required:
   - apigee-custom-httpdigest-20230117.jar
   - slf4j-api-1.7.32.jar
   - slf4j-simple-1.7.32.jar

2. include an XML file for the Java callout policy in your
   apiproxy/resources/policies directory. It should look
   like this:

   ```xml
   <JavaCallout name='Java-Compute-Http-Digest-Header' continueOnError='true'>
     <Properties>
        ....
     </Properties>
     <ClassName>com.google.apigee.callouts.HttpDigest</ClassName>
     <ResourceURL>java://apigee-custom-httpdigest-20230117.jar</ResourceURL>
   </JavaCallout>
   ```

3. Attach that policy in the right place in your API Proxy.

3. use the Apigee UI, or a command-line tool like
   [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js) or
   [apigeetool](https://github.com/apigee/apigeetool-node)
   or similar to
   import the proxy into an Apigee organization, and then deploy the proxy .
   Eg, `./importAndDeploy.js --token $TOKEN -v -o ${ORG} -e ${ENV} -d bundle/`

4. Use a client to generate and send http requests to the proxy you just deployed . Eg,
   ```
   # Apigee Edge
   endpoint=https://${ORG}-${ENV}.apigee.net
   # Apigee X/hybrid
   endpoint=https://your-custom-domain.apis.net

   curl -i $endpoint/http-digest/auth/Mufasa/VerySecret
   ```

   More examples follow below.


## Notes on Usage

There is one callout class, com.google.apigee.edgecallouts.HttpDigest

It accepts various parameters, and then produces an Authorization header.

## Configuring the Callout

### Example 1

Basic operation:

```xml
<JavaCallout name='Java-Compute-Http-Digest-Header' continueOnError='true'>
  <Properties>
    <Property name='challenge-header'>{response.header.www-authenticate.values.string}</Property>
    <Property name='username'>{extracted.username}</Property>
    <Property name='password'>{extracted.password}</Property>
    <Property name='method'>{request.verb}</Property>
    <Property name='uri'>/target-path{proxy.pathsuffix}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.HttpDigest</ClassName>
  <ResourceURL>java://apigee-custom-httpdigest-20230117.jar</ResourceURL>
</JavaCallout>
```

The result of the callout will be, the variable `digest_computed_authzheader`
will get the generated Authorization header for the endpoint.  You can then inject that
header into a Message, and send to your desired endpoint.

### Example 2

Basic operation, but the callout sets the authorization header directly into a request message:

```xml
<JavaCallout name='Java-Compute-Http-Digest-Header' continueOnError='true'>
  <Properties>
    <Property name='challenge-header'>{response.header.www-authenticate.values.string}</Property>
    <Property name='username'>{extracted.username}</Property>
    <Property name='password'>{extracted.password}</Property>
    <Property name='method'>{request.verb}</Property>
    <Property name='uri'>/target-path{proxy.pathsuffix}</Property>

    <!-- the message to get the computed header: -->
    <Property name='message'>destinationMessage</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.HttpDigest</ClassName>
  <ResourceURL>java://apigee-custom-httpdigest-20230117.jar</ResourceURL>
</JavaCallout>
```

Here, the variable `digest_computed_authzheader` will get the computed
Authorization header for the endpoint.  Also, the message `destinationMessage`
will get the appropriate authorization header inserted into it.
That destination message must exist prior to invoking the Java callout.


## Example API Proxy

You can find an example proxy bundle that uses the policy, [here in this repo](bundle/apiproxy).

This proxy targets an endpoint at httpbin.org which supports HTTP Digest authentication.

It works in this way:
1. connect to the endpoint with no Authorization header
2. receive a 401 in response, with the  WWW-Authenticate header
3. Create a new request message
3. pass that header and some authentication parameters to the Java callout to compute an Authorization header
4. use ServiceCallout to send the newly-created request message to the target

You must deploy the proxy before you can invoke it.

Start a trace before invoking the proxy.
Send a GET to `/http-digest/auth/foo/bar` to see it working.


## Building

Building from source requires Java 1.8, and Maven 3.5.

1. unpack (if you can read this, you've already done that).

2. Before building _the first time_, configure the build on your machine by loading the Apigee jars into your local cache:
  ```
  ./buildsetup.sh
  ```

3. Build with maven.
  ```
  mvn clean package
  ```
  This will build the jar and also run all the tests, and copy the jar to the resource directory in the sample apiproxy bundle.


## Runtime Dependencies

SLF4J jars.


## License

This material is Copyright (c) 2017-2023 Google LLC.
and is licensed under the [Apache 2.0 License](LICENSE). This includes the Java code as well as the API Proxy configuration.

## Bugs

* no support for qop=auth-int
