import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { getSignedUrl as awsGetSignedUrl } from "@aws-sdk/s3-request-presigner";

const BUCKET_NAME = process.env.S3_BUCKET_NAME || "securenexus-platform-557845624595";
const REGION = "us-east-1";

const s3Client = new S3Client({ region: REGION });

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
  const command = new ListObjectsV2Command({
    Bucket: BUCKET_NAME,
    Prefix: prefix || undefined,
  });
  const result = await s3Client.send(command);
  return (result.Contents || []).map((item) => ({
    key: item.Key,
    size: item.Size,
    lastModified: item.LastModified,
    etag: item.ETag,
  }));
}
