import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.File;
import java.util.Base64;

public class ValidateSSLCertMain
{

   private static String identityKeyStoreType;
   private static String identityKeyStoreFileName;
   private static String identityKeyStorePassPhrase;
   private static String identityKeyPass;

   private static String trustKeyStoreType;
   private static String trustKeyStoreFileName;
   private static String trustKeyStorePassPhrase;
   private static String trustKeyPass;

   private static HTTPSServer server;

   public static void main(String[] args)
   {
       try
        {

           if(args.length != 4 && args.length != 8)
            {
                 StringBuffer usageString = new StringBuffer();
                 usageString.append("Invalid Arguments: Please provide identityKeyStoreType info or both identityKeyStoreType and trustKeyStoreType info");
                 usageString.append("Usage: java -classpath $CLASSPATH ValidateSSLCertMain <identityKeystoreType> <identityKeyStoreFileName> <identityKeyStorePassPhrase> <identityKeyPass> ");
                 usageString.append("[<trustKeyStoreType>] [<trustKeyStoreFileName>] [<trustKeyStorePassPhrase]> [<trustKeyPass]>");
                 System.out.println(usageString);
                 System.exit(1);
            }

            String identityKeystoreType=args[0];
            String identityKeyStoreFileName=args[1];
            String identityKeyStorePassPhrase=args[2];
            String identityKeyPass=args[3];

            String trustKeyStoreType = null;
            String trustKeyStoreFileName = null;
            String trustKeyStorePassPhrase = null;
            String trustKeyPass = null;

            if(args.length > 4)
            {
                trustKeyStoreType=args[4];
                trustKeyStoreFileName=args[5];
                trustKeyStorePassPhrase=args[6];
                trustKeyPass=args[7];
            }

            if(startServerAndValidateCert(identityKeystoreType,identityKeyStoreFileName,identityKeyStorePassPhrase,
                identityKeyPass,trustKeyStoreType,trustKeyStoreFileName,trustKeyStorePassPhrase,trustKeyPass))
            {
               System.out.println("Certificates Validated Successfully");
               System.exit(0);
            }
            else
            {
               System.out.println("Certificate Validation Failed !!");
               System.exit(1);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.out.println("Error occured while executing Validator Program "+e.getMessage());
            System.exit(1);
        }
    }

    public static boolean startServerAndValidateCert(String identityKeyStoreType,String identityKeyStoreFileName,String identityKeyStorePassPhrase,
                  String identityKeyPass,String trustKeyStoreType,String trustKeyStoreFileName,String trustKeyStorePassPhrase, String trustKeyPass)
    {
        try
        {
            server = new HTTPSServer(identityKeyStoreType,identityKeyStoreFileName,identityKeyStorePassPhrase,identityKeyPass,
                                     trustKeyStoreType,trustKeyStoreFileName,trustKeyStorePassPhrase,trustKeyPass);
            server.start();
            System.out.println("Waiting for Server to Start ...");
            Thread.sleep(2000);
            return server.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK();
        } 
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
        finally
        {
            cleanup();

            if(server != null)
                server.shutdown();
        }
    }

    private static void cleanup()
    {
        try
        {
            System.out.println("Cleaning up temporary files...");

            File identityKeyStoreFile = new File("/tmp/identityKeyStoreFile.keystore");
            File trustKeyStoreFile = new File("/tmp/trustKeyStoreFile.keystore");

            if(identityKeyStoreFile.delete())
                System.out.println("Deleted temp identityKeyStoreFile");

            if(trustKeyStoreFile.delete())
                System.out.println("Deleted temp trustKeyStoreFile");
            
            System.out.println("Cleaning up temporary files... completed");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.out.println("Error while cleaning up temp keystore file");
        }




    }

}
