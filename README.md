# Cloud Direct Download Example

This project gives a simple example of how to download a blob from cloud storage using signed URLs in which the Content-Type and Content-Disposition headers are specified.   Both Microsoft Azure Blob Storage and Amazon Web Services S3 cloud storage services are included in this example.

This project also showcases a reported issue for the Azure SDK for Java, issue [2900](https://github.com/Azure/azure-sdk-for-java/issues/2900), in which properly setting the Content-Disposition header for the response doesn't function as expected.

The project can be run simply from the command-line as follows:

`mvn clean test -Dazure.config=<path/to/azure/config> -Ds3.config=<path/to/s3/config>`

Be sure to set the "azure.config" and "s3.config" properties on the command-line.  These should each point to a simple properties file containing values needed to connect to cloud storage in order to execute the test.

For Azure, the properties that need to be set are:
* **accountName** - The name of your Azure storage account.
* **accountKey** - A valid access key for your Azure storage account.
* **container** - The name of the container to store data in.  This container must exist before the test begins.

For S3, the properties that need to be set are:
* **accessKey** - The access key for your S3 account.
* **secretKey** - The secret key for your S3 account.
* **s3Region** - The region in which your bucket is located.
* **s3Bucket** - The name of the S3 bucket to store data in.  This bucket must exist before the test begins.

When the test executes, it does the same activity for both services:
* First, it uploads a blob consisting of randomly generated binary content and using a randomly generated name.
* Next, a signed URL is generated for that blob, during which the values that should be returned for the Content-Type and Content-Disposition response headers are specified.
* Next, the code attempts to download the content in the blob, verifying that a successful HTTP response is received (200).
* If the download is successful, the test then verifies that the Content-Type and Content-Disposition headers in the response were set correctly.
* Finally, the test validates that the content is the same content that was originally stored.
* At the end of the test any blobs created are cleaned up.

At present, this code manifests the issue reported in Azure SDK for Java [2900](https://github.com/Azure/azure-sdk-for-java/issues/2900), which is that a properly formatted value specified for the response's Content-Disposition header results in a 403 response for the HTTP request instead of a 200 response.  In the code, in `src/test/java/org/mvryan/example/CDDExampleTest.java` in the `createSignedAzureBlobStorageDownloadURL` method, there's a commented-out line that if uncommented will specify a value for the Content-Disposition that is not [RFC-8187](https://tools.ietf.org/html/rfc8187) compliant.  In this case the request to the URL will succeed with a 200 response, but of course the validation of the Content-Disposition header fails because the header was not set in a standards-compliant format.
