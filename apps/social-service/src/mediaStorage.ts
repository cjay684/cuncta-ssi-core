import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client
} from "@aws-sdk/client-s3";
import { NodeHttpHandler } from "@aws-sdk/node-http-handler";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { randomUUID } from "node:crypto";
import sharp from "sharp";
import { config } from "./config.js";

const MEDIA_DELETE_CONCURRENCY = 5;

const s3 = new S3Client({
  region: config.MEDIA_S3_REGION,
  endpoint: config.MEDIA_S3_ENDPOINT,
  forcePathStyle: config.MEDIA_S3_FORCE_PATH_STYLE,
  requestHandler: new NodeHttpHandler({
    connectionTimeout: config.MEDIA_S3_CONNECTION_TIMEOUT_MS,
    socketTimeout: config.MEDIA_S3_SOCKET_TIMEOUT_MS
  }),
  credentials: {
    accessKeyId: config.MEDIA_S3_ACCESS_KEY_ID,
    secretAccessKey: config.MEDIA_S3_SECRET_ACCESS_KEY
  }
});

const withTimeoutAbort = async <T>(ms: number, fn: (signal: AbortSignal) => Promise<T>) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("media_s3_op_timeout"), ms);
  timeout.unref?.();
  let timedOut = false;
  controller.signal.addEventListener(
    "abort",
    () => {
      if (controller.signal.reason === "media_s3_op_timeout") {
        timedOut = true;
      }
    },
    { once: true }
  );
  try {
    return await fn(controller.signal);
  } catch (error) {
    if (timedOut) {
      throw new Error(`media_s3_operation_timed_out:${ms}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
};

const sendS3 = <T>(command: unknown) =>
  withTimeoutAbort(
    config.MEDIA_S3_OP_TIMEOUT_MS,
    (abortSignal) =>
      s3.send(command as Parameters<typeof s3.send>[0], {
        abortSignal
      }) as Promise<T>
  );

const extByMime: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif"
};

const toBuffer = async (body: unknown): Promise<Buffer> => {
  if (!body) return Buffer.alloc(0);
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof (body as { transformToByteArray?: () => Promise<Uint8Array> }).transformToByteArray === "function") {
    return Buffer.from(await (body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray());
  }
  const reader = body as AsyncIterable<Uint8Array>;
  const chunks: Buffer[] = [];
  for await (const chunk of reader) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
};

const sanitizeOwnerPrefix = (ownerHash: string) => ownerHash.slice(0, 16);

export const buildMediaObjectKey = (input: {
  ownerSubjectHash: string;
  mimeType: string;
  kind: "original" | "thumb";
}) => {
  const ext = extByMime[input.mimeType] ?? "bin";
  const prefix = sanitizeOwnerPrefix(input.ownerSubjectHash);
  const id = randomUUID();
  return `${input.kind}/${prefix}/${id}.${ext}`;
};

export const createPresignedUpload = async (input: {
  objectKey: string;
  mimeType: string;
  ownerSubjectHash: string;
  sha256Hex: string;
  byteSize: number;
}) => {
  const command = new PutObjectCommand({
    Bucket: config.MEDIA_S3_BUCKET,
    Key: input.objectKey,
    ContentType: input.mimeType,
    ContentLength: input.byteSize,
    Metadata: {
      owner_hash: input.ownerSubjectHash,
      sha256_hex: input.sha256Hex
    }
  });
  const uploadUrl = await getSignedUrl(s3, command, { expiresIn: config.MEDIA_PRESIGN_TTL_SECONDS });
  return {
    uploadUrl,
    requiredHeaders: {
      "content-type": input.mimeType,
      "x-amz-meta-owner_hash": input.ownerSubjectHash,
      "x-amz-meta-sha256_hex": input.sha256Hex
    }
  };
};

export const createPresignedGet = async (input: { objectKey: string; expiresInSeconds?: number }) => {
  const requestedTtl = Math.max(1, Math.floor(input.expiresInSeconds ?? config.MEDIA_PRESIGN_TTL_SECONDS));
  const expiresIn = Math.min(requestedTtl, config.MEDIA_PRESIGN_TTL_SECONDS);
  const command = new GetObjectCommand({
    Bucket: config.MEDIA_S3_BUCKET,
    Key: input.objectKey
  });
  const url = await getSignedUrl(s3, command, { expiresIn });
  return { url, expiresIn };
};

export const verifyUploadedObject = async (input: {
  objectKey: string;
  expectedMimeType: string;
  expectedSha256Hex: string;
  expectedByteSize: number;
}) => {
  const head = await sendS3<{
    ContentLength?: number;
    Metadata?: Record<string, string>;
    ContentType?: string;
  }>(
    new HeadObjectCommand({
      Bucket: config.MEDIA_S3_BUCKET,
      Key: input.objectKey
    })
  );
  const size = Number(head.ContentLength ?? 0);
  const metadataSha = String(head.Metadata?.sha256_hex ?? "");
  const mimeType = String(head.ContentType ?? "");
  return {
    ok:
      size === input.expectedByteSize &&
      metadataSha === input.expectedSha256Hex &&
      mimeType === input.expectedMimeType,
    observedSize: size,
    observedSha256Hex: metadataSha,
    observedMimeType: mimeType
  };
};

export const generateThumbnail = async (input: {
  sourceObjectKey: string;
  ownerSubjectHash: string;
  mimeType: string;
}) => {
  const source = await sendS3<{ Body?: unknown }>(
    new GetObjectCommand({
      Bucket: config.MEDIA_S3_BUCKET,
      Key: input.sourceObjectKey
    })
  );
  const sourceBuffer = await toBuffer(source.Body);
  const thumbBuffer = await sharp(sourceBuffer)
    .resize({ width: 320, height: 320, fit: "inside", withoutEnlargement: true })
    .jpeg({ quality: 78, mozjpeg: true })
    .toBuffer();
  const thumbKey = buildMediaObjectKey({
    ownerSubjectHash: input.ownerSubjectHash,
    mimeType: "image/jpeg",
    kind: "thumb"
  });
  await sendS3(
    new PutObjectCommand({
      Bucket: config.MEDIA_S3_BUCKET,
      Key: thumbKey,
      Body: thumbBuffer,
      ContentType: "image/jpeg",
      Metadata: {
        source_key: input.sourceObjectKey,
        owner_hash: input.ownerSubjectHash
      }
    })
  );
  return thumbKey;
};

export const deleteMediaObjects = async (keys: Array<string | null | undefined>) => {
  const compact = Array.from(new Set(keys.filter((key): key is string => Boolean(key))));
  if (compact.length === 0) return;
  const failedKeys: string[] = [];
  for (let index = 0; index < compact.length; index += MEDIA_DELETE_CONCURRENCY) {
    const chunk = compact.slice(index, index + MEDIA_DELETE_CONCURRENCY);
    const settled = await Promise.allSettled(
      chunk.map((key) =>
        sendS3(
          new DeleteObjectCommand({
            Bucket: config.MEDIA_S3_BUCKET,
            Key: key
          })
        )
      )
    );
    for (let chunkIndex = 0; chunkIndex < settled.length; chunkIndex += 1) {
      if (settled[chunkIndex].status === "rejected") {
        failedKeys.push(chunk[chunkIndex]);
      }
    }
  }
  if (failedKeys.length > 0) {
    throw new Error(`media_delete_failed:${failedKeys.length}`);
  }
};
