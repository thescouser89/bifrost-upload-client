/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2024-2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.pnc.bifrost.upload;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.entity.GzipCompressingEntity;
import org.apache.hc.client5.http.entity.mime.FileBody;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.entity.mime.StringBody;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicHeader;
import org.jboss.pnc.api.bifrost.dto.Checksums;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static java.lang.String.format;

public class BifrostLogUploader {
    public static final String HEADER_PROCESS_CONTEXT = "log-process-context";
    public static final String HEADER_PROCESS_CONTEXT_VARIANT = "process-context-variant";
    public static final String HEADER_TMP = "log-tmp";
    public static final String HEADER_REQUEST_CONTEXT = "log-request-context";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_ACCEPTS = "Accept";

    private final URI bifrostUploadUrl;
    private final URI bifrostUrl;

    private final Supplier<String> authHeaderValueProvider;

    private static final ContentType PLAIN_UTF8_CONTENT_TYPE = ContentType.create("text/plain", StandardCharsets.UTF_8);
    private final BifrostHttpRequestRetryStrategy retryStrategy;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Creates a Bifrost log uploader.
     *
     * @param bifrostUrl   URL of bifrost host.
     * @param maxRetries   Number of retries to perform, when then is problem with uploading the logs.
     * @param delaySeconds Number of seconds to increase the waing time each retry. For example 10 means waiting times 10, 20, 30, 40, ...
     */
    public BifrostLogUploader(URI bifrostUrl, Supplier<String> authHeaderValueProvider, int maxRetries, int delaySeconds) {
        this.bifrostUrl = bifrostUrl;
        this.bifrostUploadUrl = bifrostUrl.resolve("/final-log/upload");

        this.authHeaderValueProvider = authHeaderValueProvider;
        this.retryStrategy = new BifrostHttpRequestRetryStrategy(maxRetries, delaySeconds);
    }

    /**
     * Uploads log file to Bifrost, but first reads it to compute checksums.
     */
    public void uploadFile(File logfile, LogMetadata metadata) throws BifrostUploadException {
        String md5Sum;
        try (ChecksumComputingStream checksums = ChecksumComputingStream.computeChecksums(Files.newInputStream(logfile.toPath()))) {
            md5Sum = checksums.getMD5Sum();
        } catch (IOException e) {
            throw new BifrostUploadException("Could not compute file checksums.", e);
        }
        uploadFile(logfile, metadata, md5Sum);
    }

    /**
     * Uploads log file to Bifrost, using the provided checksums.
     */
    public void uploadFile(File logfile, LogMetadata metadata, String md5sum) throws BifrostUploadException {
        MultipartEntityBuilder multipartEntityBuilder = prepareMetadata(metadata, md5sum);
        HttpEntity formDataEntity = multipartEntityBuilder.addPart("logfile", new FileBody(logfile)).build();
        List<Header> headers = prepareHeaders(metadata);
        upload(formDataEntity, headers);
    }

    /**
     * Uploads log from string to Bifrost, but first computes its checksums.
     */
    public void uploadString(String log, LogMetadata metadata) throws BifrostUploadException {
        String md5Sum;
        try (ChecksumComputingStream checksums = ChecksumComputingStream.computeChecksums(new ByteArrayInputStream(log.getBytes(StandardCharsets.UTF_8)))) {
            md5Sum = checksums.getMD5Sum();
        } catch (IOException e) {
            throw new BifrostUploadException("Could not compute file checksums.", e);
        }
        uploadString(log, metadata, md5Sum);
    }

    /**
     * Uploads log from string to Bifrost, using the provided checksums.
     */
    public void uploadString(String log, LogMetadata metadata, String md5sum) throws BifrostUploadException {
        MultipartEntityBuilder multipartEntityBuilder = prepareMetadata(metadata, md5sum);

        HttpEntity formDataEntity = multipartEntityBuilder.addPart("logfile", new StringBody(log, PLAIN_UTF8_CONTENT_TYPE)).build();
        List<Header> headers = prepareHeaders(metadata);
        upload(formDataEntity, headers);
    }

    /**
     * Retrieves checksums from Bifrost given context and tag.
     */
    public Checksums getChecksums(String processContext, TagOption tag) throws BifrostUploadException {
        return getChecksums(processContext, tag.getTagName());
    }

    /**
     * Retrieves checksums from Bifrost given context and tag.
     */
    public Checksums getChecksums(String processContext, String tag) throws BifrostUploadException {
        ClassicHttpRequest request = prepareChecksumRequest(processContext, tag);

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().setRetryStrategy(retryStrategy).build()) {
            return httpClient.execute(request, (response) -> handleJsonResponse(response, Checksums.class));
        } catch (IOException e) {
            throw new BifrostUploadException("Failed to retrieve checksums from Bifrost", e);
        }
    }

    /**
     * Retrieves logs from Bifrost as a InputStream given context and tag.
     *
     * The InputStream given in ReadStreamFunction is automatically closed, stream can be read directly.
     */
    public <T> T getLogs(String processContext, String tag, ReadStreamFunction<T> readStream) throws BifrostUploadException {
        return get(processContext, tag, (response -> {
            try (InputStream inputStream = BifrostLogUploader.handleISResponse(response)) {
                return readStream.apply(inputStream);
            }
        }));
    }

    /**
     * Retrieves logs from Bifrost as a String given context and tag.
     *
     * Warning, the returned String can consume a lot of memory for huge logs.
     */
    public String getStringLogs(String processContext, String tag) throws BifrostUploadException {
        return get(processContext, tag, BifrostLogUploader::handleStringResponse);
    }

    /**
     * Returns URI pointing to upload endpoint.
     */
    public URI uploadEndpoint() {
        return bifrostUploadUrl;
    }

    /**
     * Returns URI pointing to checksum endpoint given context and tag.
     */
    public URI checksumEndpoint(String processContext, String tag) {
        return bifrostUrl.resolve(format("/final-log/%s/%s/checksums", processContext, tag));
    }

    /**
     * Returns URI pointing to log endpoint given context and tag.
     */
    public URI getLogEndpoint(String processContext, String tag)  {
        return bifrostUrl.resolve(format("/final-log/%s/%s", processContext, tag));
    }

    private void upload(HttpEntity formDataEntity, List<Header> headers) {
        GzipCompressingEntity gzipped = new GzipCompressingEntity(formDataEntity);
        ClassicHttpRequest request = prepareRequest(gzipped, headers);

        try (CloseableHttpClient httpclient = HttpClientBuilder.create().setRetryStrategy(retryStrategy).build()) {
            httpclient.execute(request, BifrostLogUploader::handleUploadResponse);
        } catch (IOException e) {
            throw new BifrostUploadException("Failed to upload log to Bifrost", e);
        }
    }

    private <T> T get(String processContext, String tag, HttpClientResponseHandler<T> responseHandler) throws BifrostUploadException {
        ClassicHttpRequest request = prepareGetRequest(processContext, tag);

        try (CloseableHttpClient build = HttpClientBuilder.create().setRetryStrategy(retryStrategy).build()) {
            return build.execute(request, responseHandler);
        } catch (IOException e) {
            throw new BifrostUploadException("Failed to download logs from Bifrost", e);
        }
    }

    private ClassicHttpRequest prepareRequest(HttpEntity formDataEntity, List<Header> headers) {
        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder.post(bifrostUploadUrl).setEntity(formDataEntity);
        headers.forEach(requestBuilder::addHeader);
        return requestBuilder.build();
    }

    private ClassicHttpRequest prepareGetRequest(String processContext, String tag) {
        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder.get(getLogEndpoint(processContext, tag));
        requestBuilder.addHeader(HEADER_ACCEPTS, ContentType.TEXT_PLAIN.toString());

        return requestBuilder.build();
    }

    private ClassicHttpRequest prepareChecksumRequest(String processContext, String tag) {
        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder.get(checksumEndpoint(processContext, tag));
        requestBuilder.addHeader(HEADER_ACCEPTS, ContentType.APPLICATION_JSON.toString());

        return requestBuilder.build();
    }

    private List<Header> prepareHeaders(LogMetadata metadata) {
        List<Header> headers = new ArrayList<>();
        metadata.getHeaders().forEach((k, v) -> headers.add(new BasicHeader(k, v)));
        headers.add(new BasicHeader(HEADER_AUTHORIZATION, authHeaderValueProvider.get()));
        return headers;
    }

    private static MultipartEntityBuilder prepareMetadata(LogMetadata metadata, String md5sum) {
        MultipartEntityBuilder multipartEntityBuilder = MultipartEntityBuilder.create()
                .addPart("md5sum", new StringBody(md5sum, PLAIN_UTF8_CONTENT_TYPE))
                .addPart("endTime", new StringBody(metadata.getEndTime().toString(), PLAIN_UTF8_CONTENT_TYPE))
                .addPart("loggerName", new StringBody(metadata.getLoggerName(), PLAIN_UTF8_CONTENT_TYPE))
                .addPart("tag", new StringBody(metadata.getTag(), PLAIN_UTF8_CONTENT_TYPE));
        return multipartEntityBuilder;
    }

    private static boolean handleUploadResponse(ClassicHttpResponse response) {
        try (HttpEntity entity = response.getEntity()) {
            if (response.getCode() == 200) {
                EntityUtils.consume(entity);
                return true;
            } else {
                String message = EntityUtils.toString(entity);
                throw new BifrostUploadException("Failed to upload log to Bifrost, status " + response.getCode() + " message: " + message);
            }
        } catch (IOException | ParseException e) {
            throw new BifrostUploadException("Failed to upload log to Bifrost", e);
        }
    }

    private static InputStream handleISResponse(ClassicHttpResponse response) {
        return handleResponse(response, HttpEntity::getContent);
    }

    private static String handleStringResponse(ClassicHttpResponse response) {
        return handleResponse(response, EntityUtils::toString);
    }

    private static <T> T handleJsonResponse(ClassicHttpResponse response, Class<T> clazz) {
        return handleResponse(response, (httpEntity) -> objectMapper.readValue(httpEntity.getContent(), clazz));
    }

    private static <T> T handleResponse(ClassicHttpResponse response, EntityReadFunction<T> entityHandler) {
        try {
            HttpEntity entity = response.getEntity();
            if (response.getCode() == 200) {
                return entityHandler.apply(entity);
            } else if (response.getCode() == 204) {

                throw new BifrostUploadException("Logs missing from Bifrost, status " + response.getCode() + " message: " + response.getReasonPhrase());
            } else {

                String message;
                if (entity != null) {
                    message = EntityUtils.toString(entity);
                } else {
                    message = response.getReasonPhrase();
                }

                throw new BifrostUploadException("Failed to get checksums from Bifrost, status " + response.getCode() + " message: " + message);
            }
        } catch (IOException | ParseException e) {
            throw new BifrostUploadException("Failed to get checksums from Bifrost", e);
        }
    }

    @FunctionalInterface
    public interface ReadStreamFunction<T> {
        T apply(InputStream inputStream) throws IOException;
    }

    @FunctionalInterface
    private interface EntityReadFunction<R> {
        R apply(HttpEntity entity) throws IOException, ParseException;
    }

}
