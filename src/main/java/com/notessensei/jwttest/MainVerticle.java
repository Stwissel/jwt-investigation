package com.notessensei.jwttest;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.google.common.io.CharSink;
import com.google.common.io.CharSource;
import com.google.common.io.Files;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;
import io.netty.util.CharsetUtil;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

public class MainVerticle {

  private static final String PRIVATE_START = "-----BEGIN PRIVATE KEY-----\n";
  private static final String PRIVATE_END = "\n-----END PRIVATE KEY-----\n";
  private static final String PUBLIC_START = "-----BEGIN PUBLIC KEY-----\n";
  private static final String PUBLIC_END = "\n-----END PUBLIC KEY-----\n";
  private static final String CERT_START = "-----BEGIN CERTIFICATE-----\n";
  private static final String CERT_END = "\n-----END CERTIFICATE-----\n";

  public static void main(final String[] args) throws Exception {
    final MainVerticle v = new MainVerticle();

    final File crt = new File("test.crt");
    if (!crt.exists()) {
      // Create cert, pubkey, private key if they don't exist
      final Map<String, byte[]> keys = v.generate();
      keys.forEach(v::saveKey);
    }

    Map<String, String> loadKeys = v.loadKeys();
    v.testKeys(loadKeys);
    System.out.println("Done");

  }


  Map<String, String> loadKeys() throws IOException {
    Map<String, String> result = new HashMap<>();
    result.put("private", this.fileToKey("test.private.pem"));
    result.put("public", this.fileToKey("test.public.pem"));
    result.put("cert", this.fileToKey("test.crt"));
    return result;
  }

  Map<String, byte[]> generate() throws NoSuchAlgorithmException, OperatorCreationException,
      CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException {

    final Map<String, byte[]> result = new HashMap<>();

    // One day in the past
    final Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
    final Date notAfter = new Date(System.currentTimeMillis() + 84000000L * 366);

    final String signAlgo = "SHA256WithRSAEncryption";

    final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    final SecureRandom random = new SecureRandom();
    keyGen.initialize(2048, random);
    final KeyPair keyPair = keyGen.generateKeyPair();
    final PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();

    // Prepare the information required for generating an X.509 certificate.
    final X500Name owner = new X500Name("CN=John Doe");
    final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        owner, new BigInteger(64, random), notBefore, notAfter, owner, keyPair.getPublic());

    final ContentSigner signer = new JcaContentSignerBuilder(signAlgo).build(privateKey);
    final X509CertificateHolder certHolder = builder.build(signer);
    final X509Certificate cert = new JcaX509CertificateConverter()
        .setProvider(new BouncyCastleProvider())
        .getCertificate(certHolder);
    cert.verify(publicKey);

    result.put("public", publicKey.getEncoded());
    result.put("private", privateKey.getEncoded());
    result.put("cert", cert.getEncoded());

    return result;

  }

  PubSecKeyOptions getPubSecOptions(final Map.Entry<String, String> entry) {
    final String type = entry.getKey();
    final String keyString = entry.getValue();
    if ("cert".equals(type)) {
      return null;
    }
    System.out.println("Adding PubSec " + type);
    return new PubSecKeyOptions().setAlgorithm("RS256").setBuffer(keyString);
  }

  void keyToFile(final String destinationName, final String keyString) throws IOException {
    final File destination = new File(destinationName);
    Files.createParentDirs(destination);
    final CharSink sink = Files.asCharSink(destination, StandardCharsets.US_ASCII);
    sink.write(keyString);
    System.out.println("Created " + destination.getAbsolutePath());
  }


  String fileToKey(final String destinationName) throws IOException {
    final File destination = new File(destinationName);
    Files.createParentDirs(destination);
    final CharSource source = Files.asCharSource(destination, StandardCharsets.US_ASCII);
    System.out.println("Loading " + destination.getAbsolutePath());
    return source.read();
  }

  void saveKey(final String type, final byte[] content) {
    final String fileName;
    final String keyString;
    if (type.equals("public")) {
      fileName = "test.public.pem";
      keyString = this.stringyfy(content, MainVerticle.PUBLIC_START, MainVerticle.PUBLIC_END);
    } else if (type.equals("private")) {
      fileName = "test.private.pem";
      keyString = this.stringyfy(content, MainVerticle.PRIVATE_START, MainVerticle.PRIVATE_END);
    } else {
      fileName = "test.crt";
      keyString = this.stringyfy(content, MainVerticle.CERT_START, MainVerticle.CERT_END);
    }

    try {
      this.keyToFile(fileName, keyString);
    } catch (final IOException e) {
      e.printStackTrace();
    }
  }

  String stringyfy(final byte[] keyBytes, final boolean breaklines) {

    final ByteBuf keySrc = Unpooled.wrappedBuffer(keyBytes);
    final ByteBuf keyResult = Base64.encode(keySrc, breaklines);
    final String result = keyResult.toString(CharsetUtil.US_ASCII);
    keySrc.release();
    keyResult.release();

    return result;
  }

  String stringyfy(final byte[] keyBytes, final String startString,
      final String endString) {

    return new StringBuilder()
        .append(startString)
        .append(this.stringyfy(keyBytes, true))
        .append(endString)
        .toString();
  }


  void testKeys(final Map<String, String> keys) {
    final Vertx localVertx = Vertx.vertx();
    final JWTAuthOptions options = new JWTAuthOptions()
        .setJWTOptions(new JWTOptions().addAudience("CrashTest Dummies")
            .setIssuer("Puppet Master")
            .setLeeway(5)
            .setIgnoreExpiration(false)
            .setExpiresInMinutes(60)
            .setAlgorithm(CERT_END)
            .setAlgorithm("RS256"));

    keys.entrySet().stream()
        .map(this::getPubSecOptions)
        .filter(Objects::nonNull)
        .forEach(options::addPubSecKey);

    final JWTAuthOptions actual = new JWTAuthOptions(options);
    final JWTAuth auth = JWTAuth.create(localVertx, actual);

    System.out.println("Created " + auth.toString());

    final JsonObject claim = new JsonObject().put("sub", "Peter Pan");

    final String token = auth.generateToken(claim, options.getJWTOptions());
    System.out.println("Token:\n" + token);

    final JsonObject loginClaim = new JsonObject().put("jwt", token);
    auth.authenticate(loginClaim)
        .onSuccess(user -> System.out.println(user.attributes().encodePrettily()))
        .onFailure(err -> System.err.println(err.getMessage()));

  }

}
