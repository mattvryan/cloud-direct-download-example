/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.mvryan.cddexample;

import static com.google.common.io.ByteStreams.toByteArray;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.HttpMethod;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.RequestOptions;
import com.microsoft.azure.storage.RetryExponentialRetry;
import com.microsoft.azure.storage.RetryPolicy;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.blob.SharedAccessBlobHeaders;
import com.microsoft.azure.storage.blob.SharedAccessBlobPermissions;
import com.microsoft.azure.storage.blob.SharedAccessBlobPolicy;
import org.jetbrains.annotations.NotNull;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

public class CDDExampleTest {
    @Test
    public void testAzureDirectDownload() throws URISyntaxException, StorageException, IOException, InvalidKeyException {
        assertNotNull(absClient);
        byte[] content = randomBytes(bufferSize);
        absKey = uploadABSBlob(absClient, content);
        assertNotNull(absKey);

        URL url = createSignedAzureBlobStorageDownloadURL(absClient, absKey);
        assertNotNull(url);

        validateSignedUrl(url, content);
    }

    @Test
    public void testS3DirectDownload() throws IOException {
        assertNotNull(s3Client);
        byte[] content = randomBytes(bufferSize);
        s3Key = uploadS3Blob(s3Client, content);
        assertNotNull(s3Key);

        URL url = createSignedS3DownloadURL(s3Key);
        assertNotNull(url);

        validateSignedUrl(url, content);
    }

    private void validateSignedUrl(@NotNull final URL url, @NotNull final byte[] expectedContent) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(HttpMethod.GET.name());
        assertEquals(200, conn.getResponseCode());

        assertEquals(contentType, conn.getHeaderField("Content-Type"));
        assertEquals(getRFCCompliantContentDispositionHeader(), conn.getHeaderField("Content-Disposition"));

        assertTrue(Arrays.equals(expectedContent, toByteArray(conn.getInputStream())));
    }

    private String uploadABSBlob(@NotNull CloudBlobContainer client, @NotNull final byte[] content)
            throws URISyntaxException, StorageException {
        String key = UUID.randomUUID().toString();
        int contentLength = content.length;
        CloudBlockBlob blob = client.getBlockBlobReference(key);
        try (InputStream in = new ByteArrayInputStream(content)) {
            blob.upload(in, contentLength);
        }
        catch (IOException e) {
            fail(e.getMessage());
        }
        return key;
    }

    private URL createSignedAzureBlobStorageDownloadURL(@NotNull CloudBlobContainer client, @NotNull final String key)
            throws StorageException, URISyntaxException, InvalidKeyException, MalformedURLException {
        SharedAccessBlobHeaders headers = new SharedAccessBlobHeaders();
        headers.setContentType(contentType);
        headers.setContentDisposition(getRFCCompliantContentDispositionHeader());
        // Uncomment the line below to see Azure's service work with the invalid header
        //headers.setContentDisposition(getNonCompliantContentDispositionHeader());

        SharedAccessBlobPolicy policy = new SharedAccessBlobPolicy();
        Date expiration = Date.from(Instant.now().plusSeconds(expirationSeconds));
        policy.setSharedAccessExpiryTime(expiration);
        policy.setPermissions(EnumSet.of(SharedAccessBlobPermissions.READ));

        CloudBlockBlob blob = client.getBlockBlobReference(key);
        String sharedAccessSignagure = blob.generateSharedAccessSignature(policy, headers, null);
        String uriString = String.format("http://%s.blob.core.windows.net/%s/%s?%s",
                absAccountName, absContainer, key, sharedAccessSignagure);

        return new URL(uriString);
    }

    private String uploadS3Blob(@NotNull AmazonS3 client, @NotNull final byte[] content) {
        String key = UUID.randomUUID().toString();
        int contentLength = content.length;
        try (InputStream stream = new ByteArrayInputStream(content)) {
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(contentLength);
            client.putObject(s3Container, key, stream, metadata);
        }
        catch (IOException e) {
            fail(e.getMessage());
        }
        return key;
    }

    private URL createSignedS3DownloadURL(@NotNull final String key) {
        Map<String, String> reqParams = Maps.newHashMap();
        reqParams.put("response-content-type", contentType);
        reqParams.put("response-content-disposition", getRFCCompliantContentDispositionHeader());

        final Date expiration = new Date();
        expiration.setTime(expiration.getTime() + (expirationSeconds * 1000));

        GeneratePresignedUrlRequest req = new GeneratePresignedUrlRequest(s3Container, key)
                .withMethod(HttpMethod.GET)
                .withExpiration(expiration);

        for (Map.Entry<String, String> e : reqParams.entrySet()) {
            req.addRequestParameter(e.getKey(), e.getValue());
        }

        return s3Client.generatePresignedUrl(req);
    }

    private String getRFCCompliantContentDispositionHeader() {
        return getContentDispositionHeader(downloadName, encodedDownloadName);
    }

    private String getNonCompliantContentDispositionHeader() {
        return getContentDispositionHeader(downloadName, downloadName);
    }

    private String getContentDispositionHeader(@NotNull final String downloadName, @NotNull final String encodedDownloadName) {
        return String.format("inline; filename=\"%s\"; filename*=UTF-8''%s",
                downloadName,
                encodedDownloadName);
    }

    private static int bufferSize = 1024;
    private static int expirationSeconds = 3600;  // 1 hour
    private static final String downloadName = "My Image.jpg";
    private static final String encodedDownloadName = "My%20Image.jpg";
    private static final String contentType = "image/jpeg";

    private static CloudBlobContainer absClient = null;
    private static String absAccountName = null;
    private static String absKey = null;
    private static String absContainer = null;

    private static AmazonS3 s3Client = null;
    private String s3Key = null;
    private static String s3Container = null;

    @BeforeClass
    public static void initClouds() throws URISyntaxException, InvalidKeyException, StorageException {
        setupAzure();
        setupS3();
    }

    @After
    public void deleteBlobs() throws URISyntaxException, StorageException {
        if (null != absKey) {
            absClient.getBlockBlobReference(absKey).deleteIfExists();
        }
        if (null != s3Key) {
            s3Client.deleteObject(s3Container, s3Key);
        }
    }

    private static void setupAzure() throws URISyntaxException, InvalidKeyException, StorageException {
        Properties properties = getCfg("azure.config");
        absAccountName = properties.getProperty("accountName");
        absContainer = properties.getProperty("container");
        absClient = createAzureBlockStorageClient(absAccountName,
                properties.getProperty("accountKey"),
                absContainer);
    }

    private static CloudBlobContainer createAzureBlockStorageClient(@NotNull final String accountName,
                                                                    @NotNull final String accountKey,
                                                                    @NotNull final String container)
            throws URISyntaxException, InvalidKeyException, StorageException {
        String connectionString = String.format("DefaultEndpointsProtocol=http;AccountName=%s;AccountKey=%s",
                accountName, accountKey);
        CloudStorageAccount acct = CloudStorageAccount.parse(connectionString);
        CloudBlobClient client = acct.createCloudBlobClient();
        CloudBlobContainer containerClient = client.getContainerReference(container);
        RequestOptions options = containerClient.getServiceClient().getDefaultRequestOptions();
        options.setRetryPolicyFactory(new RetryExponentialRetry(RetryPolicy.DEFAULT_CLIENT_BACKOFF, 10));
        options.setTimeoutIntervalInMs(120000);
        return containerClient;
    }

    private static void setupS3() {
        Properties properties = getCfg("s3.config");
        s3Container = properties.getProperty("s3Bucket");
        s3Client = createS3Client(properties.getProperty("accessKey"),
                properties.getProperty("secretKey"),
                properties.getProperty("s3Region")
        );
    }

    private static AmazonS3 createS3Client(@NotNull final String accessKey,
                                           @NotNull final String secretKey,
                                           @NotNull final String region) {
        ClientConfiguration cfg = new ClientConfiguration();
        cfg.setProtocol(Protocol.HTTP);
        cfg.setConnectionTimeout(120000);
        cfg.setSocketTimeout(120000);
        cfg.setMaxConnections(20);
        cfg.setMaxErrorRetry(10);
        final AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        return AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSCredentialsProvider() {
                    public AWSCredentials getCredentials() {
                        return credentials;
                    }
                    public void refresh() { }
                })
                .withClientConfiguration(cfg)
                .withRegion(region)
                .build();
    }

    private static Properties getCfg(String envKey) {
        String cfg = System.getProperty(envKey);
        assertFalse(Strings.isNullOrEmpty(cfg));
        File cfgFile = new File(cfg);
        assertTrue(cfgFile.exists());
        Properties properties = new Properties();
        try (InputStream in = new FileInputStream(cfgFile)) {
            properties.load(in);
        }
        catch (IOException e) {
            fail(e.getMessage());
        }
        return properties;
    }

    private static byte[] randomBytes(int size) {
        long seed = DateTime.now().getMillis();
        Random r = new Random(seed);
        byte[] data = new byte[size];
        r.nextBytes(data);
        return data;
    }
}
