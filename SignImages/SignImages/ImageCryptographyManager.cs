using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace SignImages
{
    public static class ImageCryptographyManager
    {
        /// <summary>
        /// Sign the image data with the given certificate and write to the xmlFilePath
        /// </summary>
        /// <param name="imageBuffer">Image data to sign</param>
        /// <param name="certificateBuffer">Private key certificate byte[]</param>
        /// <param name="certPassword">Private key certificate Password</param>
        /// <param name="xmlFilePath">The path to save the signed XML</param>
        public static void SignImage(byte[] imageBuffer, byte[] certificateBuffer,string certPassword, string xmlFilePath)
        {
            var certificate = new X509Certificate2(certificateBuffer, certPassword);

            var xmlDocumentBuffer = SerializeImageToXML(imageBuffer);

            SignXMLDocument(xmlDocumentBuffer, certificate, xmlFilePath);
        }

        /// <summary>
        /// Verify the integrity of the image by checking the signature using the certificate public key
        /// </summary>
        /// <param name="xmlFilePath">Path to the signed xml image document</param>
        /// <param name="certificateBuffer">The public key certificate byte[] to verify the integrity of the signed xml image document</param>
        /// <returns>True - If image integrity is intact. False - If image has been tampered with</returns>
        public static bool VerifyImage(string xmlFilePath, byte[] certificateBuffer)
        {
            var certificate = new X509Certificate2(certificateBuffer);

            return VerifyXMLDocument(xmlFilePath, certificate);
        }

        /// <summary>
        /// Retrieve the image data from the signed xml document
        /// </summary>
        /// <param name="xmlFilePath">Path to the signed xml image document</param>
        /// <returns>Byte[] of the image</returns>
        public static byte[] GetImage(string xmlFilePath)
        {
            var unsignedXMLDocument = UnsignXMLDocument(xmlFilePath);

            return DeserializeXMLToImage(unsignedXMLDocument);
        }


        // ============================== Helper Methods ==============================

        /// <summary>
        /// Serialize an image byte[] to an XML byte[]
        /// </summary>
        /// <param name="imageBuffer">Byte[] of the image to be serialized into XML</param>
        /// <returns>Byte[] of the XML</returns>
        private static byte[] SerializeImageToXML(byte[] imageBuffer)
        {
            XmlSerializer x = new XmlSerializer(typeof(byte[]));

            using (MemoryStream myFileStream = new MemoryStream())
            {
                x.Serialize(myFileStream, imageBuffer);

                return myFileStream.ToArray();
            }
        }

        /// <summary>
        /// Sign the xml image document using private key certificate
        /// </summary>
        /// <param name="xmlDocumentBuffer">Byte[] of the xml image document</param>
        /// <param name="certificate">X509Certificate2 private key certificate to sign the xml document</param>
        /// <param name="signedXMLPath">Path to save the signed xml document</param>
        private static void SignXMLDocument(byte[] xmlDocumentBuffer, X509Certificate2 certificate, string signedXMLPath)
        {
            // Load xmlDocument data in to an XML Document
            XmlDocument xmlDocument = new XmlDocument();
            string xml = Encoding.UTF8.GetString(xmlDocumentBuffer);
            xmlDocument.LoadXml(xml);

            // Sign the XML document using the certificate private key
            using (var rsaKey = certificate.PrivateKey)
            {
                var signedXml = new SignedXml(xmlDocument);
                signedXml.SigningKey = rsaKey;

                var reference = new Reference();
                reference.Uri = "";

                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                signedXml.AddReference(reference);

                signedXml.ComputeSignature();

                var xmlDigitalSignature = signedXml.GetXml();

                xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, true));

                xmlDocument.Save(signedXMLPath);
            }
        }

        /// <summary>
        /// Verify the integrity of the signed XML document
        /// </summary>
        /// <param name="xmlFilePath">Path to the signed xml document</param>
        /// <param name="certificate">X509Certificate2 Public key certificate</param>
        /// <returns></returns>
        private static bool VerifyXMLDocument(string xmlFilePath, X509Certificate2 certificate)
        {
            var xmlDocument = ReadXMLDocumentFromPath(xmlFilePath);

            var signedXml = new SignedXml(xmlDocument);

            // Load the XML Signature
            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Verify the integrity of the xml document
            using (var rsaKey = certificate.PublicKey.Key)
            {
                return signedXml.CheckSignature(rsaKey);
            }
        }

        /// <summary>
        /// Remove the Signature from signed XML document
        /// </summary>
        /// <param name="xmlFilePath">Path to the signed xml document</param>
        /// <returns>The unsigned xml document</returns>
        private static XmlDocument UnsignXMLDocument(string xmlFilePath)
        {
            var xmlDocument = ReadXMLDocumentFromPath(xmlFilePath);

            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            xmlDocument.DocumentElement.RemoveChild(nodeList[0]);

            return xmlDocument;
        }

        /// <summary>
        /// Deserialize the unsigned xml document and retrieve the image
        /// </summary>
        /// <param name="xmlDocument">Unsigned XmlDocument</param>
        /// <returns>Byte[] of the image</returns>
        private static byte[] DeserializeXMLToImage(XmlDocument xmlDocument)
        {
            StringWriter stringWriter = new StringWriter();
            XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);

            // Save Xml Document to Text Writter.
            xmlDocument.WriteTo(xmlTextWriter);
            UTF8Encoding encoding = new UTF8Encoding();

            // Convert Xml Document To Byte Array.
            byte[] xmlDocumentBuffer = encoding.GetBytes(stringWriter.ToString());

            XmlSerializer mySerializer = new XmlSerializer(typeof(byte[]));

            using (MemoryStream myFileStream = new MemoryStream(xmlDocumentBuffer))
            {
                return (byte[])mySerializer.Deserialize(myFileStream);
            }
        }

        /// <summary>
        /// Read the XML document from image path
        /// </summary>
        /// <param name="xmlFilePath">Path the xml document to read</param>
        /// <returns>XmlDocument instance</returns>
        private static XmlDocument ReadXMLDocumentFromPath(string xmlFilePath)
        {
            // Read XML Document
            var xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(xmlFilePath);

            return xmlDocument;
        }
    }
}
