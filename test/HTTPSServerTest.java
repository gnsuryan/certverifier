import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

public class HTTPSServerTest
{
    private static HTTPSServer server;

    @After
    public void tearDown() throws Exception
    {
        Thread.sleep(2000);
        if (server != null)
        {
            server.shutdown();
        }
    }

    @Test
    public void testJKSWithBothIdentityAndTrustKeyStores()
    {
        try
        {
            System.out.println("################### testJKSWithBothIdentityAndTrustKeyStores #################");
            String identityKeyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="jks";
            String trustJKS="trust.jks";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithBothIdentityAndTrustKeyStores #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPKCS12WithBothIdentityAndTrustKeyStores()
    {
        try
        {
            System.out.println("################### testPKCS12WithBothIdentityAndTrustKeyStores #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="pkcs12";
            String trustJKS="trust.p12";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12WithBothIdentityAndTrustKeyStores #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithOnlyIdentityKeyStore()
    {
        try
        {
            System.out.println("################### testJKSWithOnlyIdentityKeyStore #################");
            String identityKeyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType=null;
            String trustJKS=null;
            String trustKeyStorePass=null;
            String trustKeyPass=null;

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithOnlyIdentityKeyStore #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKSWithOnlyIdentityKeyStore Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPKCS12WithOnlyIdentityKeyStore()
    {
        try
        {
            System.out.println("################### testPKCS12WithOnlyIdentityKeyStore #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType=null;
            String trustJKS=null;
            String trustKeyStorePass=null;
            String trustKeyPass=null;

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testPKCS12WithOnlyIdentityKeyStore Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12WithOnlyIdentityKeyStore #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
    }

    @Test
    public void testJKSWithInvalidKeyStores()
    {
        try
        {
            System.out.println("################### testJKSWithInvalidKeyStores #################");
            String identityKeyStoreType="jks";
            String identityJKS="invalidIdentity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";

            String trustKeyStoreType="jks";
            String trustJKS="invalidTrust.jks";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed !! Expected non-200 response from server",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithInvalidKeyStores #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPKCS12WithInvalidKeyStores()
    {
        try
        {
            System.out.println("################### testPKCS12WithInvalidKeyStores #################");
            
            String identityKeyStoreType="pkcs12";
            String identityJKS="invalidIdentity.p12";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="pkcs12";
            String trustJKS="invalidTrust.p12";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";
            
            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed. Excepted non-200 response !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12WithInvalidKeyStores #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithWrongIdentityKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testJKSWithWrongIdentityKeyStorePassphrase #################");
            String identityKeyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeystorePass="wrongpassword";      
            String identityKeyPass="wrongpassword";
            String trustKeyStoreType="jks";
            String trustJKS="trust.jks";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed !! Expected server start to fail",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithWrongIdentityKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPKCS12WithWrongIdentityKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testPKCS12WithWrongIdentityKeyStorePassphrase #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeystorePass="wrongpassword";
            String identityKeyPass="wrongpassword";
            String trustKeyStoreType="pkcs12";
            String trustJKS="trust.p12";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12WithWrongIdentityKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testPKCS12 Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithWrongTrustKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testJKSWithWrongTrustKeyStorePassphrase #################");
            String identityKeyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="jks";
            String trustJKS="trust.jks";
            String trustKeyStorePass="wrongpassword";
            String trustKeyPass="wrongpassword";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed !! Expected server start to fail",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithWrongTrustKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPKCS12WithWrongTrustKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testPKCS12WithWrongTrustKeyStorePassphrase #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="pkcs12";
            String trustJKS="trust.p12";
            String trustKeyStorePass="wrongpassword";
            String trustKeyPass="wrongpassword";
            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertFalse("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12WithWrongTrustKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithUnrelatedTrustKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testJKSWithUnrelatedTrustKeyStorePassphrase #################");
            String identityKeyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="jks";
            String trustJKS="unrelatedTrust.jks";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !!",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithUnrelatedTrustKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithUnrelatedIdentityKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testJKSWithUnrelatedIdentityKeyStorePassphrase #################");
            String identityKeyStoreType="jks";
            String identityJKS="unrelatedIdentity.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType="jks";
            String trustJKS="trust.jks";
            String trustKeyStorePass="Gumby12340987";
            String trustKeyPass="Gumby12340987";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! Expected server start to fail",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithUnrelatedIdentityKeyStorePassphrase #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSForOHSSetup()
    {
        try
        {
            System.out.println("################### testJKSForOHSSetup #################");
            String identityKeyStoreType="jks";
            String identityJKS="selfOHS.jks";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";
            String trustKeyStoreType=null;
            String trustJKS=null;
            String trustKeyStorePass=null;
            String trustKeyPass=null;

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testJKSForOHSSetup #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testJKSForOHSSetup Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPCKS12ForOHSSetup()
    {
        try
        {
            System.out.println("################### testPKCS12ForOHSSetup #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="selfOHS.p12";
            String identityKeystorePass="Gumby12340987";
            String identityKeyPass="Gumby12340987";

            String trustKeyStoreType=null;
            String trustJKS=null;
            String trustKeyStorePass=null;
            String trustKeyPass=null;

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPKCS12ForOHSSetup #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testPKCS12ForOHSSetup Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testPFXCertificateForAppGateway()
    {
        try
        {
            System.out.println("################### testPFXCertificateForAppGateway #################");
            String identityKeyStoreType="pkcs12";
            String identityJKS="certificate.pfx";
            String identityKeystorePass="Azure123456!";
            String identityKeyPass="Azure123456!";
            String trustKeyStoreType=null;
            String trustJKS=null;
            String trustKeyStorePass=null;
            String trustKeyPass=null;

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();
            
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            
            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());
            
            System.out.println("Test passed successfully");
            System.out.println("################### testPFXCertificateForAppGateway #################");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testPFXCertificateForAppGateway Test. Test Failed !!");
        }
        
    }

    @Test
    public void testJKSWithDifferentKeyPassAndStorePass()
    {
        try
        {
            System.out.println("################### testJKSWithDifferentKeyPassAndStorePass #################");
            String identityKeyStoreType="jks";
            String identityJKS="DifferentKeyPassStorePassIdentity.jks";
            String identityKeystorePass="DemoIdentityKeyStorePassPhrase";
            String identityKeyPass="DemoIdentityPassPhrase";

            String trustKeyStoreType="jks";
            String trustJKS="DifferentKeyPassStorePassTrust.jks";
            String trustKeyStorePass="DemoTrustKeyStorePassPhrase";
            String trustKeyPass="DemoTrustKeyStorePassPhrase";

            server = new HTTPSServer(identityKeyStoreType,identityJKS,identityKeystorePass,identityKeyPass,trustKeyStoreType,trustJKS,trustKeyStorePass,trustKeyPass);
            server.start();

            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);

            assertTrue("testJKS Failed !! ",server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK());

            System.out.println("Test passed successfully");
            System.out.println("################### testJKSWithDifferentKeyPassAndStorePass #################");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Error occured while executing testPFXCertificateForAppGateway Test. Test Failed !!");
        }
    }
}
