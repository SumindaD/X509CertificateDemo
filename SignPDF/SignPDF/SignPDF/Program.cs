using GemBox.Pdf;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignPDF
{
    class Program
    {
        static void Main(string[] args)
        {
            // If using Professional version, put your serial key below.
            ComponentInfo.SetLicense("FREE-LIMITED-KEY");

            using (var document = PdfDocument.Load("Test.pdf"))
            {
                // Add an invisible signature field to the PDF document.
                var signatureField = document.Form.Fields.AddSignature();

                // Initiate signing of a PDF file with the specified digital ID file and the password.
                signatureField.Sign("PrivateKeyCert.pfx", "1234");

                // Finish signing of a PDF file.
                document.Save("SignedDocument.pdf");
            }

            Console.WriteLine("Signed!");
            Console.ReadLine();
        }
    }
}
