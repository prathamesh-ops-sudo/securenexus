import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { getSignedUrl as awsGetSignedUrl } from "@aws-sdk/s3-request-presigner";
import { config } from "./config";
import { getAwsClientConfig } from "./aws-credentials";
import { createHash } from "node:crypto";

const BUCKET_NAME = config.aws.s3BucketName;

const s3Client = new S3Client(getAwsClientConfig());

export async function uploadFile(key: string, body: Buffer | string, contentType: string) {
  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    Body: body,
    ContentType: contentType,
  });
  const result = await s3Client.send(command);
  return { key, bucket: BUCKET_NAME, etag: result.ETag };
}

export async function createPresignedPutUrl(
  key: string,
  contentType: string,
  checksumSha256: string,
  expiresIn = 900,
): Promise<string> {
  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    ContentType: contentType,
    ChecksumSHA256: checksumSha256,
  });
  return awsGetSignedUrl(s3Client, command, {
    expiresIn,
    unhoistableHeaders: new Set(["x-amz-checksum-sha256"]),
  });
}

export async function verifyObject(key: string): Promise<{
  size: number;
  etag: string;
  checksumSha256: string;
  contentType: string;
}> {
  const head = await s3Client.send(
    new HeadObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ChecksumMode: "ENABLED",
    }),
  );
  if (head.ContentLength === undefined || !head.ETag || !head.ContentType) {
    throw new Error("Uploaded object metadata is incomplete");
  }

  let checksumSha256 = head.ChecksumSHA256;
  if (!checksumSha256) {
    const object = await s3Client.send(new GetObjectCommand({ Bucket: BUCKET_NAME, Key: key }));
    if (!object.Body) throw new Error("Uploaded object body is unavailable for checksum verification");
    const hash = createHash("sha256");
    for await (const chunk of object.Body as AsyncIterable<Uint8Array>) {
      hash.update(chunk);
    }
    checksumSha256 = hash.digest("base64");
  }

  return {
    size: head.ContentLength,
    etag: head.ETag.replace(/^"|"$/g, ""),
    checksumSha256,
    contentType: head.ContentType,
  };
}

export async function getSignedUrl(key: string, expiresIn = 3600) {
  const command = new GetObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });
  const url = await awsGetSignedUrl(s3Client, command, { expiresIn });
  return url;
}

export async function deleteFile(key: string) {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });
  await s3Client.send(command);
  return { key, deleted: true };
}

export async function listFiles(prefix?: string) {
  const allItems: Array<{
    key: string | undefined;
    size: number | undefined;
    lastModified: Date | undefined;
    etag: string | undefined;
  }> = [];
  let continuationToken: string | undefined;

  do {
    const command = new ListObjectsV2Command({
      Bucket: BUCKET_NAME,
      Prefix: prefix || undefined,
      ContinuationToken: continuationToken,
    });
    const result = await s3Client.send(command);
    if (result.Contents) {
      allItems.push(
        ...result.Contents.map((item) => ({
          key: item.Key,
          size: item.Size,
          lastModified: item.LastModified,
          etag: item.ETag,
        })),
      );
    }
    continuationToken = result.IsTruncated ? result.NextContinuationToken : undefined;
  } while (continuationToken);

  return allItems;
}
