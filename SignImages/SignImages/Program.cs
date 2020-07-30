using System;
using System.IO;

namespace SignImages
{
    class Program
    {
        static void Main(string[] args)
        {
            const string PrivateKeryCertName = "PrivateKeyCert.pfx";
            const string PublicKeyCertName = "Certificate.crt";
            const string PrivateKeryCertPassword = "1234";
            const string ImageFilePath = "Image.png";
            const string SignedXMLDocumentPath = "SignedXML.xml";
            const string RecreatedImagePath = "RecreatedImage.png";

            if (!File.Exists(PrivateKeryCertName))
                Console.WriteLine(PrivateKeryCertName + " file does not exists!");
            else if (!File.Exists(ImageFilePath))
                Console.WriteLine(ImageFilePath + " file does not exists!");
            else 
            {
                if (!File.Exists(SignedXMLDocumentPath))
                {
                    Console.WriteLine("Signing the Image");

                    ImageCryptographyManager.SignImage(File.ReadAllBytes(ImageFilePath), File.ReadAllBytes(PrivateKeryCertName), PrivateKeryCertPassword, SignedXMLDocumentPath);
                    
                    Console.WriteLine("Image signed as XML");
                }
                else 
                {
                    var integrityCheckPassed = ImageCryptographyManager.VerifyImage(SignedXMLDocumentPath, File.ReadAllBytes(PublicKeyCertName));

                    if (integrityCheckPassed) 
                    {
                        Console.WriteLine("Image integrity Intact!");

                        var imageBuffer = ImageCryptographyManager.GetImage(SignedXMLDocumentPath);

                        File.WriteAllBytes(RecreatedImagePath, imageBuffer);

                        Console.WriteLine("Image Unsigned and re-created!");
                    }
                    else
                        Console.WriteLine("Image has been tampered with!");
                }
                    
            }


            Console.ReadLine();
        }
    }
}
