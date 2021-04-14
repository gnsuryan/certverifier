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

        validateArgs(args);

        if(startServerAndValidateCert())
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

    public static void validateArgs(String[] args)
    {
        if(args.length != 4 && args.length != 8)
        {
             StringBuffer usageString = new StringBuffer();
             usageString.append("Invalid Arguments: Please provide identityKeyStoreType info or both identityKeyStoreType and trustKeyStoreType info");
             usageString.append("Usage: java -classpath $CLASSPATH ValidateSSLCertMain <identityKeystoreType> <identityKeyStoreBase64String> <identityKeyStorePassPhraseBase64String> <identityKeyPassBase64String> ");
             usageString.append("[<trustKeyStoreType>] [<trustKeyStoreBase64String>] [<trustKeyStorePassPhraseBase64String]> [<trustKeyPassBase64String]>");
             System.out.println(usageString);
             System.exit(1);
        }

        for(int i=0;i<args.length;i++)
            System.out.println(" ["+i+"] : "+args[i]);

        try
        {
            identityKeyStoreType=args[0];
            identityKeyStorePassPhrase = new String(Base64.getDecoder().decode(args[2]));
            identityKeyPass = new String(Base64.getDecoder().decode(args[3]));

            OutputStream identityFileOS = null;
            try
            {
                byte[] identityKeyStoreBase64Bytes = Base64.getDecoder().decode(args[1]);
                identityKeyStoreFileName="/tmp/identityKeyStoreFile.keystore";
                File identityKeyStoreFile = new File(identityKeyStoreFileName);
                identityKeyStoreFile.delete();
                identityFileOS = new FileOutputStream(identityKeyStoreFile);
                identityFileOS.write(identityKeyStoreBase64Bytes);
  
            }
            catch (Exception fw)
            {
                fw.printStackTrace();
            }
            finally
            {
                if( identityFileOS != null)
                    identityFileOS.close();
            }

            if(args.length == 8)
            {
                OutputStream trustFileOS = null;
                trustKeyStoreType = args[4];
                trustKeyStorePassPhrase = new String(Base64.getDecoder().decode(args[6]));
                trustKeyPass = new String(Base64.getDecoder().decode(args[6]));
                
                try
                {
                    byte[] trustKeyStoreBase64Bytes = Base64.getDecoder().decode(args[5]);
                    trustKeyStoreFileName="/tmp/trustKeyStoreFile.keystore";
                    File trustKeyStoreFile = new File(trustKeyStoreFileName);
                    trustKeyStoreFile.delete();
                    trustFileOS = new FileOutputStream(trustKeyStoreFile);
                    trustFileOS.write(trustKeyStoreBase64Bytes);

                }
                catch (Exception fw1)
                {
                    fw1.printStackTrace();
                }
                finally
                {
                    if( trustFileOS != null)
                        trustFileOS.close();
                }
            }
            else
            {
                trustKeyStoreType = null;
                trustKeyStoreFileName = null;
                trustKeyStorePassPhrase = null;
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        
    }


    public static boolean startServerAndValidateCert()
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