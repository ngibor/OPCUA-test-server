package cz.vutbr.feec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.client.security.ClientCertificateValidator;
import org.eclipse.milo.opcua.stack.client.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.core.util.NonceUtil;
import org.eclipse.milo.opcua.stack.server.EndpointConfiguration;
import org.eclipse.milo.opcua.stack.server.security.DefaultServerCertificateValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.*;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

public class OPCUAServer {

    private static final Logger log = LoggerFactory.getLogger(OPCUAServer.class);

    private static final int TCP_BIND_PORT = 12686;
    private static final int HTTPS_BIND_PORT = 8443;
    private static final String CLIENT_KEYSTORE = "client.pkcs12";
    private static final String SERVER_KEYSTORE = "server.pkcs12";
    private static final String CLIENT_ALIAS = "client";
    private static final String SERVER_ALIAS = "server";
    private static final Path CERTIFICATES_ROOT = new File(OPCUAServer.class.getClassLoader().getResource("certificates").getPath()).toPath();

    private final OpcUaServer server;
    private final TestNamespace exampleNamespace;
    private final String applicationUri;

    private static Predicate<EndpointDescription> endpointFilter() {
        return e -> SecurityPolicy.Basic256Sha256.getUri().equals(e.getSecurityPolicyUri());
    }

    static {
        // Required for SecurityPolicy.Aes256_Sha256_RsaPss
        Security.addProvider(new BouncyCastleProvider());

        try {
            NonceUtil.blockUntilSecureRandomSeeded(10, TimeUnit.SECONDS);
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static void main(String[] args) throws Exception {
        OPCUAServer server = new OPCUAServer();
        server.startup().get();

        final CompletableFuture<Void> future = new CompletableFuture<>();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> future.complete(null)));

        KeyStoreLoader clientKeyStoreLoader = new KeyStoreLoader().load(CERTIFICATES_ROOT, CLIENT_KEYSTORE, CLIENT_ALIAS);

        DefaultTrustListManager trustListManager = new DefaultTrustListManager(CERTIFICATES_ROOT.toFile());
        DefaultClientCertificateValidator certificateValidator =
                new DefaultClientCertificateValidator(trustListManager);

        // Start new client thread that will update TestNamespace.DYNAMIC_NODE_ID value to random value every 10 seconds
        new Thread(() -> {
            try {
                OpcUaClient client = OpcUaClient.create(
                        "opc.tcp://localhost:12686/milo",
                        endpoints ->
                                endpoints.stream().filter(endpointFilter())
                                        .findFirst(),
                        configBuilder ->
                                configBuilder
                                        .setApplicationName(LocalizedText.english("Server's client"))
                                        .setApplicationUri("opcua:test:client")
                                        .setRequestTimeout(uint(5000))
                                        .setKeyPair(clientKeyStoreLoader.getKeyPair())
                                        .setCertificate(clientKeyStoreLoader.getCertificate())
                                        .setCertificateChain(clientKeyStoreLoader.getCertificateChain())
                                        .setCertificateValidator(certificateValidator)
                                        .setIdentityProvider(new AnonymousProvider())
                                        .build()
                );
                client.connect().get();

                Random r = new Random();
                while (true) {
                    double randomValue = 15 * r.nextDouble();
                    DecimalFormat df = new DecimalFormat("#.##");
                    randomValue = Double.valueOf(df.format(randomValue));

                    Variant variant = new Variant(randomValue);
                    DataValue dv = new DataValue(variant, null, null);
                    client.writeValue(new NodeId(2, TestNamespace.CHANGING_NODE), dv);
                    log.info("STATIC NODE VALUE: " + client.readValue(0.0, TimestampsToReturn.Both, new NodeId(2, TestNamespace.STATIC_NODE)).get().getValue().getValue());
                    Thread.sleep(10000);
                }
            } catch (Exception e) {
                log.error("Exception raised in client thread:" + e.getMessage());
                System.exit(1);
            }
        }).start();

        future.get();
    }

    public OPCUAServer() throws Exception {
        KeyStoreLoader loader =  new KeyStoreLoader().load(CERTIFICATES_ROOT, SERVER_KEYSTORE, SERVER_ALIAS);

        DefaultCertificateManager certificateManager = new DefaultCertificateManager(
                loader.getKeyPair(),
                loader.getCertificateChain()
        );

        DefaultTrustListManager trustListManager = new DefaultTrustListManager(CERTIFICATES_ROOT.toFile());
        DefaultServerCertificateValidator certificateValidator =
                new DefaultServerCertificateValidator(trustListManager);

        UsernameIdentityValidator identityValidator = new UsernameIdentityValidator(
                true,
                authChallenge -> {
                    String username = authChallenge.getUsername();
                    String password = authChallenge.getPassword();

                    boolean userOk = "user".equals(username) && "user".equals(password);
                    boolean adminOk = "admin".equals(username) && "admin".equals(password);

                    return userOk || adminOk;
                }
        );

        X509IdentityValidator x509IdentityValidator = new X509IdentityValidator(c -> true);

        // If you need to use multiple certificates you'll have to be smarter than this.
        X509Certificate certificate = certificateManager.getCertificates()
                .stream()
                .findFirst()
                .orElseThrow(() -> new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "no certificate found"));

        KeyPair httpsKeyPair = certificateManager.getKeyPairs()
                .stream()
                .findFirst()
                .orElseThrow(() -> new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "no keypair"));

        applicationUri = CertificateUtil
                .getSanUri(certificate)
                .orElseThrow(() -> new UaRuntimeException(
                        StatusCodes.Bad_ConfigurationError,
                        "certificate is missing the application URI"));

        Set<EndpointConfiguration> endpointConfigurations = createEndpointConfigurations(certificate);

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
                .setApplicationUri(applicationUri)
                .setApplicationName(LocalizedText.english("Eclipse Milo OPC UA Example Server"))
                .setEndpoints(endpointConfigurations)
                .setCertificateManager(certificateManager)
                .setTrustListManager(trustListManager)
                .setCertificateValidator(certificateValidator)
                .setHttpsKeyPair(httpsKeyPair)
                .setHttpsCertificateChain(new X509Certificate[]{certificate})
                .setIdentityValidator(new CompositeValidator(identityValidator, x509IdentityValidator))
                .setProductUri(applicationUri)
                .build();

        server = new OpcUaServer(serverConfig);

        exampleNamespace = new TestNamespace(server);
        exampleNamespace.startup();
    }

    private Set<EndpointConfiguration> createEndpointConfigurations(X509Certificate certificate) {

        Set<EndpointConfiguration> endpointConfigurations = new LinkedHashSet<>();

        List<String> bindAddresses = newArrayList();
        bindAddresses.add("0.0.0.0");

        Set<String> hostnames = new LinkedHashSet<>();
        hostnames.add(HostnameUtil.getHostname());

        for (String bindAddress : bindAddresses) {
            for (String hostname : hostnames) {
                EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
                        .setBindAddress(bindAddress)
                        .setHostname(hostname)
                        .setPath("/milo")
                        .setCertificate(certificate)
                        .addTokenPolicies(
                                USER_TOKEN_POLICY_ANONYMOUS,
                                USER_TOKEN_POLICY_USERNAME,
                                USER_TOKEN_POLICY_X509);


                EndpointConfiguration.Builder noSecurityBuilder = builder.copy()
                        .setSecurityPolicy(SecurityPolicy.None)
                        .setSecurityMode(MessageSecurityMode.None);

                endpointConfigurations.add(buildTcpEndpoint(noSecurityBuilder));
                endpointConfigurations.add(buildHttpsEndpoint(noSecurityBuilder));

                // TCP Basic256Sha256 / SignAndEncrypt
                endpointConfigurations.add(buildTcpEndpoint(
                        builder.copy()
                                .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                                .setSecurityMode(MessageSecurityMode.SignAndEncrypt))
                );

                // HTTPS Basic256Sha256 / Sign (SignAndEncrypt not allowed for HTTPS)
                endpointConfigurations.add(buildHttpsEndpoint(
                        builder.copy()
                                .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                                .setSecurityMode(MessageSecurityMode.Sign))
                );

                /*
                 * It's good practice providing a discovery-specific endpoint with no security.
                 * It's required practice if all regular endpoints have security configured.
                 *
                 * Usage of the  "/discovery" suffix is defined by OPC UA Part 6:
                 *
                 * Each OPC UA Server Application implements the Discovery Service Set. If the OPC UA Server requires a
                 * different address for this Endpoint it shall create the address by appending the path "/discovery" to
                 * its base address.
                 */

                EndpointConfiguration.Builder discoveryBuilder = builder.copy()
                        .setPath("/milo/discovery")
                        .setSecurityPolicy(SecurityPolicy.None)
                        .setSecurityMode(MessageSecurityMode.None);

                endpointConfigurations.add(buildTcpEndpoint(discoveryBuilder));
                endpointConfigurations.add(buildHttpsEndpoint(discoveryBuilder));
            }
        }

        return endpointConfigurations;
    }

    private static EndpointConfiguration buildTcpEndpoint(EndpointConfiguration.Builder base) {
        return base.copy()
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .setBindPort(TCP_BIND_PORT)
                .build();
    }

    private static EndpointConfiguration buildHttpsEndpoint(EndpointConfiguration.Builder base) {
        return base.copy()
                .setTransportProfile(TransportProfile.HTTPS_UABINARY)
                .setBindPort(HTTPS_BIND_PORT)
                .build();
    }

    public OpcUaServer getServer() {
        return server;
    }

    public CompletableFuture<OpcUaServer> startup() {
        return server.startup();
    }

    public CompletableFuture<OpcUaServer> shutdown() {
        exampleNamespace.shutdown();

        return server.shutdown();
    }
}
