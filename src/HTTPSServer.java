import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

/*
 * https://www.robinhowlett.com/blog/2016/01/05/everything-you-ever-wanted-to-know-about-ssl-but-were-afraid-to-ask/
 */
public class HTTPSServer
{

    private static final String JAVA_KEYSTORE = "jks";
    private static final String PKCS12_KEYSTORE = "pkcs12";
    private static final boolean ONE_WAY_SSL = false; // no client certificates
    private static final int listenPort = 8901;

    public HttpServer server;
    public SSLContext serverSSLContext;
    private CloseableHttpClient httpclient;
    private String keystoreType;
    private String identityKeyStore;
    private String trustKeyStore;
    private String identityKeyStorePassPhrase;
    private String trustKeyStorePassPhrase;

    public HTTPSServer(String keystoreType, String identityKeyStore, String trustKeyStore,
            String identityKeyStorePassPhrase, String trustKeyStorePassPhrase) throws Exception
    {
        this.setKeystoreType(keystoreType);
        this.setIdentityKeyStore(identityKeyStore);
        this.setTrustKeyStore(trustKeyStore);
        this.setIdentityKeyStorePassPhrase(identityKeyStorePassPhrase);
        this.setTrustKeyStorePassPhrase(trustKeyStorePassPhrase);

        validateInput(keystoreType, identityKeyStore, trustKeyStore, identityKeyStorePassPhrase,
                trustKeyStorePassPhrase);
    }

    public void start() throws Exception
    {
        Runnable runnableServerThread = new Runnable()
        {
            @Override
            public void run()
            { // anonymous class
                System.out.println("Starting server using Runnable Thread with Anonymous Class");

                initializeAndStartServer();
            }
        };

        Thread serverThread = new Thread(runnableServerThread);
        serverThread.start();
    }

    public static void main(String args[])
    {
        try
        {

            if (args.length != 5)
            {
                System.out.println("[Error]: Invalid Arguments ");
                System.out.println(
                        "Usage: java -classpath $CLASSPATH HTTPServer <keystoreType> <identityKeystore> <trustKeystore> <identityKeyStorePassPhrase> <trustKeyStorePassPhrase>");
                System.out.println(
                        "Usage: java -classpath $CLASSPATH HTTPServer jks identity.jks trust.jks changeme changeme");
                System.exit(1);
            }

            String keystoreType = args[0];
            String identityKeyStore = args[1];
            String trustKeyStore = args[2];
            String identityKeyStorePassPhrase = args[3];
            String trustKeyStorePassPhrase = args[4];

            HTTPSServer httpsServer = new HTTPSServer(keystoreType, identityKeyStore, trustKeyStore,
                    identityKeyStorePassPhrase, trustKeyStorePassPhrase);
            httpsServer.start();
            // httpsServer.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK();
        } catch (Exception e)
        {
            System.out.println("Error in creating HTTPSServer " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void validateInput(String keystoreType, String identityKeyStore, String trustKeyStore,
            String identityKeyStorePassPhrase, String trustKeyStorePassPhrase)
    {
        if ((!JAVA_KEYSTORE.equalsIgnoreCase(keystoreType)) && (!PKCS12_KEYSTORE.equalsIgnoreCase(keystoreType)))
        {
            System.out.println("[Error]: Invalid keystoreType : " + keystoreType);
            System.exit(1);
        }
    }

    public void initializeAndStartServer()
    {
        try
        {
            httpclient = HttpClients.createDefault();
            SSLContext serverSSLContext = createServerSSLContext(this.identityKeyStore,
                    this.identityKeyStorePassPhrase.toCharArray());

            System.out.println("Creating Local Server listening on port 8901");
            server = createLocalTestServer(serverSSLContext, ONE_WAY_SSL);
            server.start();

        } catch (Exception e)
        {
            System.out.println("Error in initializing and Starting HTTPSServer " + e.getMessage());
            e.printStackTrace();
        }

    }

    protected HttpServer createLocalTestServer(SSLContext sslContext, boolean forceSSLAuth) throws UnknownHostException
    {
        final HttpServer server = ServerBootstrap.bootstrap().setLocalAddress(InetAddress.getLocalHost())
                .setListenerPort(listenPort).setSslContext(sslContext)
                .setSslSetupHandler(socket -> socket.setNeedClientAuth(forceSSLAuth))
                .registerHandler("*", (request, response, context) -> response.setStatusCode(HttpStatus.SC_OK))
                .create();

        return server;
    }

    /**
     * KeyStores provide credentials, TrustStores verify credentials.
     *
     * Server KeyStores stores the server's private keys, and certificates for
     * corresponding public keys. Used here for HTTPS connections over localhost.
     *
     * Client TrustStores store servers' certificates.
     */
    protected KeyStore getStore(final String storeFileName, final char[] password)
            throws Exception
    {
        InputStream inputStream = null;
        KeyStore store = null;
        try
        {
            store = KeyStore.getInstance(JAVA_KEYSTORE);
            URL url = HTTPSServer.class.getClassLoader().getResource(storeFileName);

            if(url == null)
                throw new Exception("Resource "+storeFileName+" not found");

            inputStream = url.openStream();

            //InputStream inputStream = new FileInputStream(new File(storeFileName));
           
            store.load(inputStream, password);
        }
        catch(Exception e)
        {
            e.printStackTrace();
            throw new Exception("Error occuring while loading provided keystore: "+e.getMessage());
        }
        finally
        {
            if(inputStream != null)
                inputStream.close();
        }

        return store;
    }

    /**
     * KeyManagers decide which authentication credentials (e.g. certs) should be
     * sent to the remote host for authentication during the SSL handshake.
     *
     * Server KeyManagers use their private keys during the key exchange algorithm
     * and send certificates corresponding to their public keys to the clients. The
     * certificate comes from the KeyStore.
     */
    protected KeyManager[] getKeyManagers(KeyStore store, final char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException
    {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(store, password);

        return keyManagerFactory.getKeyManagers();
    }

    /**
     * TrustManagers determine if the remote connection should be trusted or not.
     *
     * Clients will use certificates stored in their TrustStores to verify
     * identities of servers. Servers will use certificates stored in their
     * TrustStores to verify identities of clients.
     */
    protected TrustManager[] getTrustManagers(KeyStore store) throws NoSuchAlgorithmException, KeyStoreException
    {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(store);

        return trustManagerFactory.getTrustManagers();
    }

    /*
     * Create an SSLContext for the server using the server's JKS. This instructs
     * the server to present its certificate when clients connect over HTTPS.
     */
    protected SSLContext createServerSSLContext(final String storeFileName, final char[] password)
            throws Exception
    {
        KeyStore serverKeyStore = getStore(storeFileName, password);
        KeyManager[] serverKeyManagers = getKeyManagers(serverKeyStore, password);
        TrustManager[] serverTrustManagers = getTrustManagers(serverKeyStore);

        SSLContext sslContext = SSLContexts.custom().useProtocol("TLS").build();
        sslContext.init(serverKeyManagers, serverTrustManagers, new SecureRandom());

        return sslContext;
    }

    public String getIdentityKeyStore()
    {
        return identityKeyStore;
    }

    public void setIdentityKeyStore(String identityKeyStore)
    {
        this.identityKeyStore = identityKeyStore;
    }

    public String getTrustKeyStore()
    {
        return trustKeyStore;
    }

    public void setTrustKeyStore(String trustKeyStore)
    {
        this.trustKeyStore = trustKeyStore;
    }

    public Object getIdentityKeyStorePassPhrase()
    {
        return identityKeyStorePassPhrase;
    }

    public void setIdentityKeyStorePassPhrase(String identityKeyStorePassPhrase)
    {
        this.identityKeyStorePassPhrase = identityKeyStorePassPhrase;
    }

    public String getTrustKeyStorePassPhrase()
    {
        return trustKeyStorePassPhrase;
    }

    public void setTrustKeyStorePassPhrase(String trustKeyStorePassPhrase)
    {
        this.trustKeyStorePassPhrase = trustKeyStorePassPhrase;
    }

    public boolean httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK() throws Exception
    {
        try
        {
            
            String baseUrl = getBaseUrl(server);
    
            // The server certificate was imported into the client's TrustStore (using
            // keytool -import)
            
            KeyStore clientTrustStore = null;
            
            if(trustKeyStore != null)
            {
                 System.out.println("Setting provided trustkeystore");
                 clientTrustStore = getStore(trustKeyStore, trustKeyStorePassPhrase.toCharArray());
            }
            else
            {
                System.out.println("Setting identity keystore itself as trustkeystore");
                clientTrustStore = getStore(identityKeyStore, identityKeyStorePassPhrase.toCharArray());
            }
            
            SSLContext sslContext = new SSLContextBuilder()
                    .loadTrustMaterial(clientTrustStore, new TrustSelfSignedStrategy()).build();
    
            SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
    
            httpclient = HttpClients.custom().setSSLSocketFactory(csf).setSSLContext(sslContext).build();

            // The HTTP client will now validate the server's presented certificate using
            // its TrustStore.
            // Since the cert was imported to the client's TrustStore explicitly (see
            // above), the
            // certificate will validate and the request will succeed

            HttpResponse httpResponse = httpclient.execute(new HttpGet("https://" + baseUrl + "/echo/this"));

            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode == 200)
            {
                System.out.println("got 200 OK response");
                return true;
            } else
                System.out.println("got non 200 response: " + statusCode);

            return false;
        } catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
    }

    protected void shutdown()
    {
        if (server != null)
            server.shutdown(1, TimeUnit.SECONDS);
        else
        {
            System.out.println("[Error]: Cannot shutdown uninitialized server ");
        }
    }

    protected String getBaseUrl(HttpServer server) throws Exception
    {
        if(server != null)
            return server.getInetAddress().getHostName() + ":" + server.getLocalPort();
        else
            throw new Exception("Unable to obtain server baseURL as server is not running");
    }

    public String getKeystoreType()
    {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType)
    {
        this.keystoreType = keystoreType;
    }

}