import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";

export type LogSourceProbeResult = {
  sourceType: string;
  tested: boolean;
  timestamp: string;
  status: "success" | "error" | "unavailable";
  message: string;
  reasonCode?: "configuration" | "authentication" | "permission" | "network" | "not_found" | "unknown";
  eventReceipt?: {
    eventsReceived: number;
    lastEventAt: Date | string | null;
    everReceived: boolean;
  };
};

export function mapCloudWatchProbeError(error: unknown): Pick<LogSourceProbeResult, "reasonCode" | "message"> {
  const candidate = error as { name?: string; Code?: string; code?: string; message?: string };
  const errorCode = candidate.name || candidate.Code || candidate.code;
  const message = candidate.message || "CloudWatch probe failed.";

  if (errorCode === "CredentialsProviderError" || errorCode === "UnauthenticatedException") {
    return { reasonCode: "authentication", message: `CloudWatch authentication failed: ${message}` };
  }
  if (
    errorCode === "AccessDeniedException" ||
    errorCode === "UnauthorizedOperation" ||
    errorCode === "UnrecognizedClientException"
  ) {
    return { reasonCode: "permission", message: `CloudWatch permission denied: ${message}` };
  }
  if (
    errorCode === "TimeoutError" ||
    errorCode === "NetworkingError" ||
    errorCode === "RequestTimeout" ||
    errorCode === "ETIMEDOUT" ||
    errorCode === "ECONNRESET" ||
    errorCode === "ENOTFOUND"
  ) {
    return { reasonCode: "network", message: `CloudWatch network request failed: ${message}` };
  }
  return { reasonCode: "unknown", message: `CloudWatch probe failed: ${message}` };
}

export function buildHttpPushProbeResult(source: {
  sourceType: string;
  httpEndpoint: string | null;
  eventsReceived: number;
  lastEventAt: Date | string | null;
}): LogSourceProbeResult {
  const everReceived = source.eventsReceived > 0 || source.lastEventAt !== null;
  return {
    sourceType: source.sourceType,
    tested: false,
    timestamp: new Date().toISOString(),
    status: "unavailable",
    message: everReceived
      ? `Cannot verify an HTTP push source from this side. The source must send an event to ${source.httpEndpoint || "the configured receiver"}; ${source.eventsReceived} event(s) have arrived, most recently ${String(source.lastEventAt)}.`
      : `Cannot verify an HTTP push source from this side. The source must send an event to ${source.httpEndpoint || "the configured receiver"}; no events have been received yet.`,
    reasonCode: "configuration",
    eventReceipt: {
      eventsReceived: source.eventsReceived,
      lastEventAt: source.lastEventAt,
      everReceived,
    },
  };
}

export async function probeCloudWatchLogSource(source: {
  sourceType: string;
  cloudwatchRegion: string | null;
  cloudwatchLogGroup: string | null;
}): Promise<LogSourceProbeResult> {
  const timestamp = new Date().toISOString();
  if (!source.cloudwatchRegion || !source.cloudwatchLogGroup) {
    return {
      sourceType: source.sourceType,
      tested: false,
      timestamp,
      status: "error",
      message: "CloudWatch probe could not run because region and log group are required.",
      reasonCode: "configuration",
    };
  }

  try {
    const client = new CloudWatchLogsClient({ region: source.cloudwatchRegion });
    const response = await client.send(
      new DescribeLogGroupsCommand({
        logGroupNamePrefix: source.cloudwatchLogGroup,
        limit: 50,
      }),
    );
    const found = (response.logGroups || []).some((group) => group.logGroupName === source.cloudwatchLogGroup);
    if (!found) {
      return {
        sourceType: source.sourceType,
        tested: true,
        timestamp,
        status: "error",
        message: `CloudWatch log group "${source.cloudwatchLogGroup}" was not found in ${source.cloudwatchRegion}.`,
        reasonCode: "not_found",
      };
    }
    return {
      sourceType: source.sourceType,
      tested: true,
      timestamp,
      status: "success",
      message: `CloudWatch access verified for log group "${source.cloudwatchLogGroup}" in ${source.cloudwatchRegion}.`,
    };
  } catch (error) {
    const mapped = mapCloudWatchProbeError(error);
    return {
      sourceType: source.sourceType,
      tested: true,
      timestamp,
      status: "error",
      ...mapped,
    };
  }
}
