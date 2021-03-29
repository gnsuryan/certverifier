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
            String keyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS="trust.jks";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeyPass="Gumby12340987";
            String trustJKS="trust.p12";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="identity.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS=null;
            String trustKeyPass=null;
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeyPass="Gumby12340987";
            String trustJKS=null;
            String trustKeyPass=null;
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="jks";
            String identityJKS="invalidIdentity.jks";
            String trustJKS="invalidTrust.jks";
            String identityKeyPass="Gumby12340987";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            
            String keyStoreType="pkcs12";
            String identityJKS="invalidIdentity.p12";
            String identityKeyPass="Gumby12340987";            
            String trustJKS="invalidTrust.p12";
            String trustKeyPass="Gumby12340987";
            
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeyPass="wrongpassword";
            String trustJKS="trust.jks";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeyPass="wrongpassword";
            String trustJKS="trust.p12";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            fail("Error occured while executing testJKS Test. Test Failed !!");
        }
        
    }
    
    @Test
    public void testJKSWithWrongTrustKeyStorePassphrase()
    {
        try
        {
            System.out.println("################### testJKSWithWrongTrustKeyStorePassphrase #################");
            String keyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS="trust.jks";
            String trustKeyPass="wrongpassword";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="identity.p12";
            String identityKeyPass="Gumby12340987";
            String trustJKS="trust.p12";
            String trustKeyPass="wrongpassword";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="jks";
            String identityJKS="identity.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS="unrelatedTrust.jks";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="jks";
            String identityJKS="unrelatedIdentity.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS="trust.jks";
            String trustKeyPass="Gumby12340987";
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="selfOHS.jks";
            String identityKeyPass="Gumby12340987";
            String trustJKS=null;
            String trustKeyPass=null;
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="selfOHS.p12";
            String identityKeyPass="Gumby12340987";
            String trustJKS=null;
            String trustKeyPass=null;
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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
            String keyStoreType="pkcs12";
            String identityJKS="certificate.pfx";
            String identityKeyPass="Azure123456!";
            String trustJKS=null;
            String trustKeyPass=null;
            server = new HTTPSServer(keyStoreType,identityJKS,trustJKS,identityKeyPass,trustKeyPass);
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

}
