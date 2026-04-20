export interface NormalizedAlert {
  source: string;
  sourceEventId: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  rawData: any;
  normalizedData: any;
  sourceIp?: string;
  destIp?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  userId?: string;
  hostname?: string;
  fileHash?: string;
  url?: string;
  domain?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  detectedAt?: Date;
}
